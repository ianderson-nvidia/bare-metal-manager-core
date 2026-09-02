/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use ::rpc::protos;
use carbide_uuid::domain::DomainId;
use db::db_read::DbReader;
use db::dns::resource_record;
use dns_record::{DnsResourceRecordReply, DnsResourceRecordType, SoaRecord};
use model::dns::{Answer, AuthorityRef, Fqdn, LookupOutcome, ResourceRecord};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

#[derive(Clone, Debug)]
struct DnsResourceRecordLookupResponse {
    record: Vec<DnsResourceRecordReply>,
    outcome: LookupOutcome,
    authoritative: bool,
    authority_soa: Option<DnsResourceRecordReply>,
}

impl DnsResourceRecordLookupResponse {
    fn new(
        record: Vec<DnsResourceRecordReply>,
        outcome: LookupOutcome,
        authoritative: bool,
        authority_soa: Option<DnsResourceRecordReply>,
    ) -> Self {
        Self {
            record,
            outcome,
            authoritative,
            authority_soa,
        }
    }

    fn from_answer(answer: Answer) -> Self {
        let wire = answer.lookup_wire();
        match answer {
            Answer::Records { records, .. } => Self::new(
                records.into_iter().map(Into::into).collect(),
                wire.outcome,
                wire.authoritative,
                None,
            ),
            Answer::NoData { authority, soa } => Self::new(
                vec![],
                wire.outcome,
                wire.authoritative,
                Some(authority_soa_reply(authority.zone(), &soa)),
            ),
            Answer::NxDomain { authority, soa } => Self::new(
                vec![],
                wire.outcome,
                wire.authoritative,
                Some(authority_soa_reply(authority.zone(), &soa)),
            ),
            Answer::NotAuthoritative | Answer::Refused | Answer::NotImplemented => {
                Self::new(vec![], wire.outcome, wire.authoritative, None)
            }
        }
    }
}

fn authority_soa_reply(zone: &Fqdn, soa: &SoaRecord) -> DnsResourceRecordReply {
    DnsResourceRecordReply {
        qtype: DnsResourceRecordType::SOA.to_string(),
        qname: zone.as_str().to_string(),
        ttl: soa.ttl.0 as u32,
        content: soa.to_string(),
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

/// Publish a zone SOA as a lookup `ResourceRecord` at the zone apex.
fn soa_as_model(authority: &AuthorityRef, soa: &SoaRecord) -> ResourceRecord {
    ResourceRecord {
        q_type: DnsResourceRecordType::SOA.to_string(),
        q_name: authority.zone().as_str().to_string(),
        ttl: soa.ttl.0 as u32,
        content: soa.to_string(),
        domain_id: None,
    }
}

/// The zone we hold that a queried name falls under.
struct HeldAuthority {
    authority: AuthorityRef,
    /// The zone's SOA. `None` if the `domains` row has none; the zone can then
    /// return records but not NODATA or NXDOMAIN, which need an SOA.
    soa: Option<SoaRecord>,
    /// The queried name is the zone name itself, not something under it.
    is_apex: bool,
}

/// Find which of our zones contains `qname`.
///
/// Checks every live `domains` row. If `qname` is the row's name or ends with
/// it (by whole labels, so `notmysite.example.com` is not under
/// `mysite.example.com`), the row is a candidate. If several match, the one
/// with the most labels wins. Returns `None` if none match.
async fn find_site_authority(
    db: impl DbReader<'_>,
    qname: &Fqdn,
) -> Result<Option<HeldAuthority>, Status> {
    let domains =
        db::dns::domain::find_by(db, db::ObjectColumnFilter::<db::dns::domain::IdColumn>::All)
            .await
            .map_err(CarbideError::from)?;

    let closest = domains
        .into_iter()
        .filter_map(|domain| {
            // A row that cannot be parsed can never answer, so every name under
            // it silently becomes NOTAUTH. Make that visible.
            let zone = match Fqdn::parse(&domain.name) {
                Ok(zone) => zone,
                Err(error) => {
                    tracing::warn!(
                        domain_id = %domain.id,
                        name = %domain.name,
                        %error,
                        "skipping DNS domain with an unparsable name"
                    );
                    return None;
                }
            };
            qname.is_within(&zone).then_some((domain, zone))
        })
        .max_by_key(|(_, zone)| zone.as_str().len());

    let Some((domain, zone)) = closest else {
        return Ok(None);
    };
    Ok(Some(HeldAuthority {
        is_apex: qname == &zone,
        authority: AuthorityRef::Site {
            domain: domain.id,
            zone,
        },
        soa: domain.soa.map(|soa| soa.0),
    }))
}

impl From<DnsResourceRecordLookupResponse> for protos::dns::DnsResourceRecordLookupResponse {
    fn from(value: DnsResourceRecordLookupResponse) -> Self {
        Self {
            records: value.record.into_iter().map(Into::into).collect(),
            outcome: protos::dns::DnsLookupOutcome::from(value.outcome) as i32,
            authority_soa: value.authority_soa.map(Into::into),
            authoritative: value.authoritative,
        }
    }
}

/// Returns all published record types for a qname. The authority layer selects the requested type.
async fn lookup_records_by_qname(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Vec<ResourceRecord>, tonic::Status> {
    tracing::debug!(query_name, "Looking up DNS records",);

    // dns_records view expects trailing dots (FQDN format)
    let qname_with_dot = if !query_name.ends_with('.') {
        format!("{}.", query_name)
    } else {
        query_name.to_string()
    };

    let result = resource_record::find_record(txn, &qname_with_dot)
        .await
        .map_err(CarbideError::from)?
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();

    Ok(result)
}

/// Resolve a reverse-DNS (PTR) query. The qname is an address in `in-addr.arpa` /
/// `ip6.arpa` form, so we parse it back to an `IpAddr` and look the holding
/// interface up by address (rather than matching a per-row arpa string in a view).
/// An unparseable name, or one no interface holds, yields no records.
async fn lookup_ptr_record(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Vec<ResourceRecord>, tonic::Status> {
    tracing::debug!(qname = %query_name, "looking up PTR record");

    let qname_with_dot = if !query_name.ends_with('.') {
        format!("{}.", query_name)
    } else {
        query_name.to_string()
    };

    let Some(address) = db::dns::arpa_qname_to_ip(&qname_with_dot) else {
        return Ok(vec![]);
    };

    let result = resource_record::find_ptr_record(txn, address)
        .await
        .map_err(CarbideError::from)?
        .into_iter()
        .map(|record| ResourceRecord {
            q_type: DnsResourceRecordType::PTR.to_string(),
            q_name: qname_with_dot.clone(),
            ttl: record.ttl as u32,
            content: record.ptr_content,
            domain_id: Some(record.domain_id.to_string()),
        })
        .collect::<Vec<_>>();

    Ok(result)
}

/// Pick an authority for a PTR record when no reverse zone contains it.
///
/// Reverse zones are only created for prefixes that end on an octet or nibble
/// boundary (/8, /16, /24, /32 for IPv4). An address on a /25 has a PTR record
/// but no `in-addr.arpa` row above it, so `find_site_authority` finds nothing.
/// Rather than drop the record, use the forward domain that owns the hostname
/// the PTR points at.
///
/// The site is the only reverse authority, so the gap can be closed by having
/// `cidr_to_reverse_zone` round a non-aligned prefix up to the enclosing
/// aligned zone. The zone row is site-wide, not per-VPC, and which name an
/// address resolves to is still decided per address by `find_ptr_record`, so
/// two segments sharing a /24 row does not change either one's answers. Zone
/// create/delete would then have to refcount by "any live prefix inside the
/// zone" instead of by exact prefix, or deleting one /25 would drop the /24
/// row the other still uses.
///
/// Allocated prefixes cannot overlap across tenants today (site-wide exclusion
/// constraints on `network_prefixes` and `network_vpc_prefixes`), so every
/// address has at most one owner and no claim or tie-break is needed here.
// TODO: remove once `cidr_to_reverse_zone` rounds up and zone refcounting is by range.
async fn ptr_forward_authority(
    db: impl DbReader<'_>,
    record: &ResourceRecord,
) -> Result<AuthorityRef, Status> {
    let domain_id = record
        .domain_id
        .as_deref()
        .and_then(|id| id.parse::<DomainId>().ok())
        .ok_or_else(|| Status::internal("PTR record is missing its owning domain id"))?;
    let domain = db::dns::domain::find_by_uuid(db, domain_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "domain",
            id: domain_id.to_string(),
        })?;
    let zone = Fqdn::parse(&domain.name).map_err(|error| {
        Status::internal(format!(
            "domain {domain_id} has an unparsable name {:?}: {error}",
            domain.name
        ))
    })?;
    Ok(AuthorityRef::Site {
        domain: domain.id,
        zone,
    })
}

/// Does anything exist below `qname`?
///
/// A name with records under it exists even if it has none of its own
/// (RFC 8020 §2). If we answer NXDOMAIN for `rack1.example.com` while
/// `gpu1.rack1.example.com` exists, a resolver may cache that and stop looking
/// up anything under `rack1`.
///
/// Reverse names are checked by address range, since PTR records are keyed by
/// address rather than stored under their arpa name.
async fn name_has_descendants(db: impl DbReader<'_>, qname: &Fqdn) -> Result<bool, Status> {
    let exists = match db::dns::arpa_qname_to_prefix(qname.as_str()) {
        Some(prefix) => resource_record::any_ptr_owner_within(db, prefix).await,
        None => resource_record::any_record_below(db, qname.as_str()).await,
    };
    Ok(exists.map_err(CarbideError::from)?)
}

/// Answer one DNS question from the zones this site holds.
///
/// The result is one of:
///
/// - `Records`: the name has records of the requested type.
/// - `NoData`: the name exists but has no records of that type. Includes the
///   zone apex, and names that only have records below them.
/// - `NxDomain`: the name is inside one of our zones and nothing exists at or
///   below it.
/// - `NotAuthoritative`: the name is not inside any zone we hold. We never say
///   NXDOMAIN for those, because the name may well exist somewhere else.
///
/// `NoData` and `NxDomain` carry the zone SOA for the authority section.
async fn lookup_answer(
    db: impl DbReader<'_> + Copy,
    qname: &str,
    qtype: DnsResourceRecordType,
) -> Result<Answer, Status> {
    let qname =
        Fqdn::parse(qname).map_err(|error| CarbideError::InvalidArgument(error.to_string()))?;
    let held = find_site_authority(db, &qname).await?;

    // PTR data is keyed by address rather than by zone, and the address may
    // sit under a prefix that has no reverse zone row (see
    // `ptr_forward_authority`). Resolve it before the zone gate so those
    // records keep being served.
    if qtype == DnsResourceRecordType::PTR {
        let records = lookup_ptr_record(db, qname.as_str()).await?;
        if let Some(first) = records.first() {
            let authority = match held {
                Some(held) => held.authority,
                None => ptr_forward_authority(db, first).await?,
            };
            return Ok(Answer::Records { authority, records });
        }
    }

    let Some(held) = held else {
        return Ok(Answer::NotAuthoritative);
    };

    // The apex SOA is the only record synthesised from the zone row rather than
    // read from inventory. NS is not published, so it falls through to NODATA.
    if held.is_apex && qtype == DnsResourceRecordType::SOA {
        let records = match &held.soa {
            Some(soa) => vec![soa_as_model(&held.authority, soa)],
            None => {
                tracing::warn!(zone = %held.authority.zone().as_str(), "held zone has no SOA");
                vec![]
            }
        };
        return Ok(Answer::Records {
            authority: held.authority,
            records,
        });
    }

    // Everything published at the exact name, any type. The PTR miss above
    // already established nothing is published at a reverse name.
    let published = if qtype == DnsResourceRecordType::PTR {
        vec![]
    } else {
        lookup_records_by_qname(db, qname.as_str()).await?
    };
    let name_exists =
        held.is_apex || !published.is_empty() || name_has_descendants(db, &qname).await?;

    let wanted = qtype.to_string();
    let records: Vec<ResourceRecord> = published
        .into_iter()
        .filter(|record| record.q_type == wanted)
        .collect();
    if !records.is_empty() {
        return Ok(Answer::Records {
            authority: held.authority,
            records,
        });
    }

    // Without an SOA there is nothing to put in the authority section, so the
    // zone can only report an empty positive answer.
    let Some(soa) = held.soa else {
        tracing::warn!(
            zone = %held.authority.zone().as_str(),
            "held zone has no SOA; cannot distinguish NODATA from NXDOMAIN"
        );
        return Ok(Answer::Records {
            authority: held.authority,
            records: vec![],
        });
    };
    Ok(if name_exists {
        Answer::NoData {
            authority: held.authority,
            soa,
        }
    } else {
        Answer::NxDomain {
            authority: held.authority,
            soa,
        }
    })
}

pub(crate) async fn get_all_domains(
    api: &Api,
    _request: Request<protos::dns::GetAllDomainsRequest>,
) -> Result<Response<protos::dns::GetAllDomainsResponse>, Status> {
    log_request_data(&_request);

    let domains = db::dns::domain::find_by(
        &api.database_connection,
        db::ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;

    tracing::debug!(domain_count = domains.len(), "Found domains");
    for domain in &domains {
        tracing::debug!(
            domain_id = %domain.id,
            domain_name = %domain.name,
            "Domain"
        );
    }

    let result: Vec<protos::dns::DomainInfo> = domains
        .into_iter()
        .map(model::dns::DomainInfo::from)
        .map(protos::dns::DomainInfo::from)
        .collect();

    let response = protos::dns::GetAllDomainsResponse { result };

    tracing::debug!(
        domain_info_count = response.result.len(),
        "Formatted DomainInfo response"
    );
    Ok(Response::new(response))
}

pub(crate) async fn get_all_domain_metadata(
    api: &Api,
    request: Request<protos::dns::DomainMetadataRequest>,
) -> Result<Response<protos::dns::DomainMetadataResponse>, Status> {
    log_request_data(&request);

    let metadata_request = request.into_inner();

    let domain_name = db::dns::normalize_domain(&metadata_request.domain);

    // Reverse zones may be stored with or without the trailing root dot, so
    // resolve their normalized identity. Forward domains retain the existing
    // exact lookup after the request normalization above.
    let domains = db::dns::domain::find_by_name(&api.database_connection, &domain_name).await?;

    let domain = domains.first().ok_or_else(|| CarbideError::NotFoundError {
        kind: "domain",
        id: metadata_request.domain.clone(),
    })?;

    let proto_metadata = domain
        .metadata
        .as_ref()
        .map(|m| protos::dns::Metadata::from(m.clone()));

    Ok(Response::new(protos::dns::DomainMetadataResponse {
        result: proto_metadata,
    }))
}
pub(crate) async fn lookup_record(
    api: &Api,
    request: Request<protos::dns::DnsResourceRecordLookupRequest>,
) -> Result<Response<protos::dns::DnsResourceRecordLookupResponse>, Status> {
    log_request_data(&request);

    let lookup_request = request.into_inner();

    // Log the full incoming request for debugging
    tracing::debug!(
        qtype = %lookup_request.qtype,
        qname = %lookup_request.qname,
        zone_id = %lookup_request.zone_id,
        "Processing DNS lookup request"
    );

    let rrtype = DnsResourceRecordType::try_from(lookup_request.qtype)
        .map_err(|e| CarbideError::InvalidArgument(format!("invalid qtype supplied: {}", e)))?;

    let qname = lookup_request.qname;

    if qname.is_empty() {
        return Err(CarbideError::InvalidArgument("qname cannot be empty".to_string()).into());
    }

    let answer = lookup_answer(&api.database_connection, &qname, rrtype).await?;
    let resp = DnsResourceRecordLookupResponse::from_answer(answer);
    Ok(Response::new(resp.into()))
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;
    use carbide_uuid::domain::DomainId;

    use super::*;

    #[test]
    fn lookup_response_mapping_copies_answer_metadata() {
        let authority = site_authority();
        value_scenarios!(
            run = |answer: Answer| {
                let proto = protos::dns::DnsResourceRecordLookupResponse::from(
                    DnsResourceRecordLookupResponse::from_answer(answer),
                );
                (
                    proto.outcome,
                    proto.authoritative,
                    proto.authority_soa.is_some(),
                    proto.records.len(),
                )
            };
            "in-zone RRset" {
                Answer::Records {
                    authority: authority.clone(),
                    records: vec![model_a_record()],
                } => (
                    protos::dns::DnsLookupOutcome::Records as i32,
                    true,
                    false,
                    1,
                ),
            }
            "empty Records is Records, not NXDOMAIN" {
                Answer::Records {
                    authority: authority.clone(),
                    records: vec![],
                } => (
                    protos::dns::DnsLookupOutcome::Records as i32,
                    true,
                    false,
                    0,
                ),
            }
            "NODATA carries authority SOA" {
                Answer::NoData {
                    authority: authority.clone(),
                    soa: dns_record::SoaRecord::new("mysite.example.com"),
                } => (
                    protos::dns::DnsLookupOutcome::NoData as i32,
                    true,
                    true,
                    0,
                ),
            }
            "NXDOMAIN carries authority SOA" {
                Answer::NxDomain {
                    authority,
                    soa: dns_record::SoaRecord::new("mysite.example.com"),
                } => (
                    protos::dns::DnsLookupOutcome::NoSuchName as i32,
                    true,
                    true,
                    0,
                ),
            }
            "not authoritative" {
                Answer::NotAuthoritative => (
                    protos::dns::DnsLookupOutcome::NotAuthoritative as i32,
                    false,
                    false,
                    0,
                ),
            }
        );
    }

    fn site_authority() -> AuthorityRef {
        AuthorityRef::Site {
            domain: DomainId::from(uuid::Uuid::nil()),
            zone: Fqdn::parse("mysite.example.com").expect("fixture zone"),
        }
    }

    fn model_a_record() -> ResourceRecord {
        ResourceRecord {
            q_type: DnsResourceRecordType::A.to_string(),
            q_name: "gpu.mysite.example.com.".to_string(),
            ttl: 300,
            content: "192.0.2.10".to_string(),
            domain_id: None,
        }
    }
}
