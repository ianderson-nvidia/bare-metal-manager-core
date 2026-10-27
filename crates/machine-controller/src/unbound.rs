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

//! Automatic per-VPC, per-DPU Unbound workloads.

use std::collections::{BTreeMap, HashMap, HashSet};

use carbide_dpf::{
    DetachedDpuServiceDefinition, DetachedDpuServiceSecurity, DetachedHelmChart,
    DetachedServiceDaemonSet, DpfError, DpuServiceObservation, NAMESPACE, OwnerReference,
};
use carbide_uuid::machine::DpuMachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use eyre::eyre;
use model::instance::config::network::{
    DeviceLocator, InstanceInterfaceConfig, InstanceNetworkConfig, InstanceNetworkConfigUpdate,
};
use model::machine::{ManagedHostState, ManagedHostStateSnapshot};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use state_controller::state_handler::StateHandlerError;

use crate::dpf::DpfOperations;

const HOST_LABEL: &str = "carbide.nvidia.com/unbound-host-id";
const VPC_LABEL: &str = "carbide.nvidia.com/unbound-vpc-id";
const DPU_LABEL: &str = "carbide.nvidia.com/dpu-machine-id";
const MANAGER_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGER: &str = "nico-unbound";
const DEVICE_API_VERSION: &str = "provisioning.dpu.nvidia.com/v1alpha1";

/// Absence leaves workloads unmanaged; an explicit disable drains owned workloads.
#[derive(Debug, Clone)]
pub enum UnboundServiceConfig {
    /// Retire owned workloads and wait until they disappear.
    Disabled,
    /// Reconcile workloads using the operator-supplied chart and native configuration.
    Enabled(DetachedHelmChart),
}

pub(crate) async fn reconcile(
    state: &ManagedHostStateSnapshot,
    config: &UnboundServiceConfig,
    sdk: &dyn DpfOperations,
    pool: &PgPool,
) -> Result<bool, StateHandlerError> {
    if !state.host_snapshot.config.dpf.used_for_ingestion {
        return Ok(true);
    }
    let host = state.host_snapshot.id.to_string();
    let desired = match (config, &state.managed_state) {
        (UnboundServiceConfig::Disabled, _)
        | (_, ManagedHostState::ForceDeletion | ManagedHostState::Decommissioning { .. }) => {
            Some(Vec::new())
        }
        (UnboundServiceConfig::Enabled(chart), _) => {
            desired_services(state, chart, sdk, pool).await?
        }
    };
    let Some(desired) = desired else {
        // Preserve workloads while the machine handler recreates missing DPF owners.
        return Ok(true);
    };
    reconcile_services(sdk, &host, &desired)
        .await
        .map_err(|error| StateHandlerError::GenericError(error.into()))
}

// `None` means owner discovery is incomplete; an empty list authorizes retirement.
async fn desired_services(
    state: &ManagedHostStateSnapshot,
    chart: &DetachedHelmChart,
    sdk: &dyn DpfOperations,
    pool: &PgPool,
) -> Result<Option<Vec<DetachedDpuServiceDefinition>>, StateHandlerError> {
    // Admin acknowledgement is the release boundary, including deleted instances.
    if !state.needs_site_prefix_isolation() {
        return Ok(Some(Vec::new()));
    }
    let instance = state.instance.as_ref().ok_or_else(|| {
        StateHandlerError::GenericError(eyre!(
            "cannot resolve unbound memberships without the instance"
        ))
    })?;
    let interfaces = membership_interfaces(
        &instance.config.network,
        instance.update_network_config_request.as_ref(),
    );
    let segment_ids = interfaces
        .iter()
        .filter(|interface| interface.vpc_id.is_none())
        .filter_map(|interface| interface.network_segment_id)
        .collect::<Vec<_>>();
    let segments = if segment_ids.is_empty() {
        HashMap::new()
    } else {
        let mut connection = pool.acquire().await?;
        db::network_segment::find_by(
            &mut *connection,
            db::ObjectColumnFilter::List(db::network_segment::IdColumn, &segment_ids),
            model::network_segment::NetworkSegmentSearchConfig::default(),
        )
        .await?
        .into_iter()
        .map(|segment| (segment.id, segment.config.vpc_id))
        .collect()
    };
    let memberships = resolve_memberships(&interfaces, state, &segments)
        .map_err(|error| StateHandlerError::GenericError(error.into()))?;
    let host = state.host_snapshot.id.to_string();
    let mut desired = Vec::new();
    let mut missing_owner = false;
    for dpu in &state.dpu_snapshots {
        let vpcs = memberships
            .iter()
            .filter(|(id, _)| id == &dpu.id)
            .map(|(_, vpc)| *vpc)
            .collect::<Vec<_>>();
        if vpcs.is_empty() {
            continue;
        }
        let dpu_id = dpu.id.to_string();
        let device_id = dpu.dpf_id().ok_or_else(|| {
            StateHandlerError::GenericError(eyre!("unbound target DPU has no DPF device identity"))
        })?;
        let Some(owner) = sdk
            .get_dpu_device_metadata(&device_id)
            .await
            .map_err(|error| StateHandlerError::GenericError(error.into()))?
        else {
            missing_owner = true;
            continue;
        };
        if owner.deletion_timestamp.is_some()
            || owner
                .labels
                .as_ref()
                .and_then(|labels| labels.get(DPU_LABEL))
                != Some(&dpu_id)
        {
            return Err(StateHandlerError::GenericError(eyre!(
                "unbound target DPUDevice identity is invalid"
            )));
        }
        let owner_uid = owner.uid.filter(|uid| !uid.is_empty()).ok_or_else(|| {
            StateHandlerError::GenericError(eyre!("unbound target DPUDevice has no UID"))
        })?;
        let labels = sdk
            .get_dpu_device_node_labels(&device_id)
            .await
            .map_err(|error| StateHandlerError::GenericError(error.into()))?;
        if labels.get(DPU_LABEL) != Some(&dpu_id) {
            sdk.merge_dpu_device_node_labels(
                &device_id,
                BTreeMap::from([(DPU_LABEL.into(), Some(dpu_id.clone()))]),
            )
            .await
            .map_err(|error| StateHandlerError::GenericError(error.into()))?;
        }
        for vpc in vpcs {
            let vpc = vpc.to_string();
            let name = service_name(&host, &vpc, &dpu_id);
            desired.push(DetachedDpuServiceDefinition {
                name: name.clone(),
                namespace: NAMESPACE.into(),
                labels: ownership_labels(&host, &vpc, &dpu_id),
                owner_references: vec![OwnerReference {
                    api_version: DEVICE_API_VERSION.into(),
                    kind: "DPUDevice".into(),
                    name: carbide_dpf::dpu_device_cr_name(&device_id),
                    uid: owner_uid.clone(),
                    controller: Some(true),
                    block_owner_deletion: Some(false),
                }],
                helm_chart: DetachedHelmChart {
                    release_name: name,
                    ..chart.clone()
                },
                deploy_in_cluster: Some(false),
                security: DetachedDpuServiceSecurity {
                    privileged: false,
                    spiffe: false,
                },
                service_daemon_set: Some(DetachedServiceDaemonSet {
                    node_selector_labels: Some(BTreeMap::from([(
                        DPU_LABEL.into(),
                        dpu_id.clone(),
                    )])),
                    ..Default::default()
                }),
                service_id: None,
                interfaces: None,
            });
        }
    }
    Ok((!missing_owner).then_some(desired))
}

fn membership_interfaces(
    current: &InstanceNetworkConfig,
    pending: Option<&InstanceNetworkConfigUpdate>,
) -> Vec<InstanceInterfaceConfig> {
    current
        .interfaces
        .iter()
        .chain(pending.into_iter().flat_map(|update| {
            update
                .old_config
                .interfaces
                .iter()
                .chain(&update.new_config.interfaces)
        }))
        .cloned()
        .collect()
}

fn resolve_memberships(
    interfaces: &[InstanceInterfaceConfig],
    state: &ManagedHostStateSnapshot,
    segments: &HashMap<NetworkSegmentId, Option<VpcId>>,
) -> Result<HashSet<(DpuMachineId, VpcId)>, DpfError> {
    if state.host_snapshot.associated_dpu_machine_ids().is_empty() {
        return Ok(HashSet::new());
    }
    let primary_ids = state
        .host_snapshot
        .status
        .interfaces
        .iter()
        .filter(|interface| interface.primary_interface)
        .filter_map(|interface| interface.attached_dpu_machine_id)
        .collect::<HashSet<_>>();
    let primary = if primary_ids.len() == 1 {
        primary_ids.iter().next().copied()
    } else {
        None
    };
    let topology = state
        .dpu_snapshots
        .iter()
        .filter_map(|dpu| {
            state
                .host_snapshot
                .get_device_locator_for_dpu_id(&dpu.id)
                .ok()
                .map(|locator| (locator, dpu.id))
        })
        .collect::<Vec<_>>();
    let mut memberships = HashSet::new();
    for interface in interfaces {
        let vpc = match interface.vpc_id {
            Some(vpc) => Some(vpc),
            None => {
                let segment = interface.network_segment_id.ok_or_else(|| {
                    DpfError::InvalidState(
                        "unbound interface has no resolved VPC or segment".into(),
                    )
                })?;
                *segments.get(&segment).ok_or_else(|| {
                    DpfError::InvalidState("unbound interface segment is absent".into())
                })?
            }
        };
        if let Some(vpc) = vpc {
            let dpu = resolve_dpu(interface.device_locator.as_ref(), primary, &topology)?;
            memberships.insert((dpu, vpc));
        }
    }
    Ok(memberships)
}

fn resolve_dpu(
    requested: Option<&DeviceLocator>,
    primary: Option<DpuMachineId>,
    topology: &[(DeviceLocator, DpuMachineId)],
) -> Result<DpuMachineId, DpfError> {
    let resolved = match requested {
        None => primary,
        Some(locator) => {
            let matches = topology
                .iter()
                .filter(|(candidate, _)| candidate == locator)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [(_, id)] => Some(*id),
                _ => None,
            }
        }
    };
    resolved.ok_or_else(|| {
        DpfError::InvalidState("unbound interface DPU is missing or ambiguous".into())
    })
}

fn service_name(host: &str, vpc: &str, dpu: &str) -> String {
    let hash = hex::encode(Sha256::digest(format!("{host}\0{vpc}\0{dpu}")));
    format!("nico-unbound-{}", &hash[..40])
}

fn ownership_labels(host: &str, vpc: &str, dpu: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (HOST_LABEL.into(), host.into()),
        (VPC_LABEL.into(), vpc.into()),
        (DPU_LABEL.into(), dpu.into()),
        (MANAGER_LABEL.into(), MANAGER.into()),
    ])
}

fn node_selector(definition: &DetachedDpuServiceDefinition) -> Option<Value> {
    let labels = definition
        .service_daemon_set
        .as_ref()?
        .node_selector_labels
        .as_ref()?;
    let expressions = labels
        .iter()
        .map(|(key, value)| json!({"key": key, "operator": "In", "values": [value]}))
        .collect::<Vec<_>>();
    Some(json!({"nodeSelectorTerms": [{"matchExpressions": expressions}]}))
}

fn owned_by_device(owner: &OwnerReference) -> bool {
    owner.api_version == DEVICE_API_VERSION
        && owner.kind == "DPUDevice"
        && owner.name.starts_with("device-")
        && !owner.uid.is_empty()
        && owner.controller == Some(true)
        && owner.block_owner_deletion == Some(false)
}

fn verify_owned(observed: &DpuServiceObservation, host: &str) -> Result<(), DpfError> {
    let (Some(vpc), Some(dpu)) = (
        observed.labels.get(VPC_LABEL),
        observed.labels.get(DPU_LABEL),
    ) else {
        return Err(DpfError::InvalidState(
            "unbound service has no VPC or DPU ownership".into(),
        ));
    };
    if observed.namespace.as_deref() != Some(NAMESPACE)
        || observed.name.as_deref() != Some(service_name(host, vpc, dpu).as_str())
        || ownership_labels(host, vpc, dpu)
            .iter()
            .any(|(key, value)| observed.labels.get(key) != Some(value))
        || observed
            .labels
            .contains_key("svc.dpu.nvidia.com/owned-by-dpudeployment")
        || !matches!(observed.owner_references.as_slice(), [owner] if owned_by_device(owner))
    {
        return Err(DpfError::InvalidState(
            "refusing to mutate a DPUService with conflicting unbound ownership".into(),
        ));
    }
    let preconditions = observed.delete_preconditions()?;
    if preconditions.uid.is_empty() || preconditions.resource_version.is_empty() {
        return Err(DpfError::InvalidState(
            "unbound service has an empty UID or resource version".into(),
        ));
    }
    Ok(())
}

async fn reconcile_services(
    sdk: &dyn DpfOperations,
    host: &str,
    desired: &[DetachedDpuServiceDefinition],
) -> Result<bool, DpfError> {
    let observed = sdk
        .list_dpu_services(Some(&format!("{HOST_LABEL}={host}")))
        .await?;
    for service in &observed {
        verify_owned(service, host)?;
    }
    for definition in desired {
        // A foreign object with this name fails the create with AlreadyExists.
        let Some(current) = observed
            .iter()
            .find(|service| service.name.as_deref() == Some(definition.name.as_str()))
        else {
            sdk.create_dpu_service(definition).await?;
            continue;
        };
        if current.owner_references != definition.owner_references {
            return Err(DpfError::InvalidState(
                "unbound service owner differs from the current DPUDevice".into(),
            ));
        }
        if current.is_deleting {
            return Ok(false);
        }
        if !matches_definition(current, definition) {
            let preconditions = current.delete_preconditions()?;
            sdk.patch_dpu_service(&definition.name, json!([
                {"op": "test", "path": "/metadata/uid", "value": preconditions.uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": preconditions.resource_version},
                {"op": "add", "path": "/spec", "value": service_spec(definition)},
            ])).await?;
        }
    }
    let mut complete = true;
    for service in observed {
        if desired
            .iter()
            .any(|definition| service.name.as_deref() == Some(definition.name.as_str()))
        {
            continue;
        }
        complete = false;
        if !service.is_deleting {
            let preconditions = service.delete_preconditions()?;
            let name = service
                .name
                .as_deref()
                .ok_or_else(|| DpfError::InvalidState("unbound service has no name".into()))?;
            sdk.delete_dpu_service(name, &preconditions).await?;
        }
    }
    Ok(complete)
}

fn service_spec(definition: &DetachedDpuServiceDefinition) -> Value {
    let daemon_set = node_selector(definition).map(|selector| json!({"nodeSelector": selector}));
    json!({
        "helmChart": {"source": {"repoURL": definition.helm_chart.repo_url, "chart": definition.helm_chart.chart, "version": definition.helm_chart.version, "releaseName": definition.helm_chart.release_name}, "values": definition.helm_chart.values},
        "deployInCluster": false, "security": {"privileged": false}, "serviceDaemonSet": daemon_set,
    })
}

fn matches_definition(
    observed: &DpuServiceObservation,
    desired: &DetachedDpuServiceDefinition,
) -> bool {
    observed.helm_chart.repo_url == desired.helm_chart.repo_url
        && observed.helm_chart.chart.as_ref() == Some(&desired.helm_chart.chart)
        && observed.helm_chart.version == desired.helm_chart.version
        && observed.helm_chart.release_name.as_ref() == Some(&desired.helm_chart.release_name)
        && observed.helm_chart.values == desired.helm_chart.values
        && !observed.deploy_in_cluster.unwrap_or(false)
        && !observed.dpu_cluster_selector_present
        && observed.interfaces.is_none()
        && !observed.paused.unwrap_or(false)
        && observed
            .security
            .as_ref()
            .is_some_and(|security| security.privileged == Some(false) && !security.spiffe)
        && observed.service_id.is_none()
        && !observed.config_ports_present
        && match (&observed.service_daemon_set, node_selector(desired)) {
            (None, None) => true,
            (Some(daemon_set), Some(selector)) => {
                daemon_set.node_selector.as_ref() == Some(&selector)
                    && daemon_set.annotations.is_none()
                    && daemon_set.labels.is_none()
                    && daemon_set.resources.is_none()
                    && daemon_set.update_strategy.is_none()
            }
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use model::test_support::machine_snapshot::dpu_machine;

    use super::*;

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn never_ingested_hosts_do_not_access_dpf() {
        use model::test_support::machine_snapshot::managed_host_state_snapshot;

        use crate::dpf::MockDpfOperations;
        let mut state = managed_host_state_snapshot();
        state.host_snapshot.config.dpf.used_for_ingestion = false;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let sdk = MockDpfOperations::new();
        for config in [
            UnboundServiceConfig::Disabled,
            UnboundServiceConfig::Enabled(test_definition("host").helm_chart),
        ] {
            assert!(reconcile(&state, &config, &sdk, &pool).await.unwrap());
        }
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn disabled_and_host_teardown_drain_without_discovery() {
        use model::test_support::machine_snapshot::managed_host_state_snapshot;

        use crate::dpf::MockDpfOperations;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for (config, managed_state) in [
            (UnboundServiceConfig::Disabled, ManagedHostState::Ready),
            (
                UnboundServiceConfig::Enabled(test_definition("host").helm_chart),
                ManagedHostState::ForceDeletion,
            ),
            (
                UnboundServiceConfig::Enabled(test_definition("host").helm_chart),
                ManagedHostState::Decommissioning {
                    decommissioning_state:
                        model::machine::DecommissioningState::SuppressingSiteExplorer,
                },
            ),
        ] {
            let mut state = managed_host_state_snapshot();
            state.host_snapshot.config.dpf.used_for_ingestion = true;
            state.host_snapshot.network_config.value.use_admin_network = Some(true);
            state.managed_state = managed_state;
            state.dpu_snapshots.clear();
            state.instance = None;
            assert!(!state.managed_host_network_config_version_synced());
            let mut sdk = MockDpfOperations::new();
            sdk.expect_list_dpu_services()
                .times(1)
                .returning(|_| Ok(vec![]));
            assert!(reconcile(&state, &config, &sdk, &pool).await.unwrap());
        }
    }

    #[test]
    fn pending_interfaces_remain_until_the_acknowledged_request_is_cleared() {
        let segment = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let first = "00000000-0000-0000-0000-000000000002".parse().unwrap();
        let second = "00000000-0000-0000-0000-000000000003".parse().unwrap();
        let third = "00000000-0000-0000-0000-000000000004".parse().unwrap();
        let current = InstanceNetworkConfig::for_segment_ids(&[segment], &[], &[first]);
        let pending = InstanceNetworkConfigUpdate {
            old_config: InstanceNetworkConfig::for_segment_ids(&[segment], &[], &[second]),
            new_config: InstanceNetworkConfig::for_segment_ids(&[segment], &[], &[third]),
        };
        for (request, expected) in [
            (Some(&pending), vec![Some(first), Some(second), Some(third)]),
            (None, vec![Some(first)]),
        ] {
            let interfaces = membership_interfaces(&current, request);
            assert_eq!(
                interfaces
                    .iter()
                    .map(|interface| interface.vpc_id)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn placement_requires_one_exact_dpu() {
        let primary = dpu_machine(0).id;
        let secondary = dpu_machine(1).id;
        let locator = DeviceLocator {
            device: "nic".into(),
            device_instance: 1,
        };
        let cases = [
            (None, vec![], Some(primary)),
            (
                Some(locator.clone()),
                vec![(locator.clone(), secondary)],
                Some(secondary),
            ),
            (Some(locator.clone()), vec![], None),
            (
                Some(locator.clone()),
                vec![(locator.clone(), primary), (locator, secondary)],
                None,
            ),
        ];
        for (requested, topology, expected) in cases {
            assert_eq!(
                resolve_dpu(requested.as_ref(), Some(primary), &topology).ok(),
                expected
            );
        }
    }

    #[test]
    fn memberships_preserve_vpc_precedence_exact_targets_and_zero_dpu_hosts() {
        use model::test_support::machine_snapshot::managed_host_state_snapshot;
        let mut state = managed_host_state_snapshot();
        let segment = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let first = "00000000-0000-0000-0000-000000000002".parse().unwrap();
        let second = "00000000-0000-0000-0000-000000000003".parse().unwrap();
        let primary = state
            .host_snapshot
            .primary_attached_dpu_machine_id()
            .unwrap();
        let secondary = state
            .dpu_snapshots
            .iter()
            .find(|dpu| dpu.id != primary)
            .unwrap()
            .id;
        let mut direct = InstanceNetworkConfig::for_segment_ids(&[segment], &[], &[first])
            .interfaces
            .remove(0);
        let mut fallback = direct.clone();
        fallback.vpc_id = None;
        fallback.device_locator = Some(
            state
                .host_snapshot
                .get_device_locator_for_dpu_id(&secondary)
                .unwrap(),
        );
        let segments = HashMap::from([(segment, Some(second))]);
        let interfaces = [direct.clone(), fallback, direct.clone()];
        assert_eq!(
            resolve_memberships(&interfaces, &state, &segments).unwrap(),
            HashSet::from([(primary, first), (secondary, second)])
        );
        direct.vpc_id = None;
        assert!(resolve_memberships(&[direct.clone()], &state, &HashMap::new()).is_err());
        state.host_snapshot.status.interfaces.clear();
        state.dpu_snapshots.clear();
        assert!(
            resolve_memberships(&[direct], &state, &HashMap::new())
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn drain_waits_for_absence_and_retries_transient_delete_failure() {
        use crate::dpf::MockDpfOperations;
        let host = "host";
        let definition = test_definition(host);
        let observed = observation(&definition);
        let mut sdk = MockDpfOperations::new();
        let mut sequence = mockall::Sequence::new();
        for fail in [true, false] {
            let observed = observed.clone();
            sdk.expect_list_dpu_services()
                .times(1)
                .in_sequence(&mut sequence)
                .returning(move |_| Ok(vec![observed.clone()]));
            sdk.expect_delete_dpu_service()
                .times(1)
                .in_sequence(&mut sequence)
                .withf(|_, preconditions| {
                    preconditions.uid == "service-uid" && preconditions.resource_version == "7"
                })
                .returning(move |_, _| {
                    if fail {
                        Err(DpfError::InvalidState("transient failure".into()))
                    } else {
                        Ok(())
                    }
                });
        }
        sdk.expect_list_dpu_services()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_| Ok(vec![]));
        assert!(reconcile_services(&sdk, host, &[]).await.is_err());
        assert!(!reconcile_services(&sdk, host, &[]).await.unwrap());
        assert!(reconcile_services(&sdk, host, &[]).await.unwrap());
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn failed_create_preserves_stale_services() {
        use crate::dpf::MockDpfOperations;
        let desired = test_definition("host");
        let mut stale = test_definition("host");
        stale.labels.insert(
            VPC_LABEL.into(),
            "00000000-0000-0000-0000-000000000002".into(),
        );
        stale.name = service_name("host", &stale.labels[VPC_LABEL], &stale.labels[DPU_LABEL]);
        let mut sdk = MockDpfOperations::new();
        let stale_observed = observation(&stale);
        sdk.expect_list_dpu_services()
            .returning(move |_| Ok(vec![stale_observed.clone()]));
        // A name collision with a foreign object surfaces here as a failed create.
        sdk.expect_create_dpu_service()
            .returning(|_| Err(DpfError::InvalidState("already exists".into())));
        // No delete expectation: the stale service outlives a failed replacement.
        assert!(reconcile_services(&sdk, "host", &[desired]).await.is_err());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn empty_revision_cannot_authorize_mutation() {
        let mut observed = observation(&test_definition("host"));
        observed.resource_version = Some(String::new());
        assert!(verify_owned(&observed, "host").is_err());
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn unchanged_service_is_not_patched_and_changed_chart_is_revision_fenced() {
        use crate::dpf::MockDpfOperations;
        for changed in [false, true] {
            let desired = test_definition("host");
            let mut current = observation(&desired);
            if changed {
                current.helm_chart.version = "old".into();
            }
            let mut sdk = MockDpfOperations::new();
            sdk.expect_list_dpu_services()
                .returning(move |_| Ok(vec![current.clone()]));
            if changed {
                let patched = observation(&desired);
                sdk.expect_patch_dpu_service().times(1).withf(|_, patch| {
                    patch[0] == json!({"op": "test", "path": "/metadata/uid", "value": "service-uid"})
                        && patch[1] == json!({"op": "test", "path": "/metadata/resourceVersion", "value": "7"})
                        && patch[2]["value"]["helmChart"]["source"]["version"] == "1"
                }).returning(move |_, _| Ok(patched.clone()));
            }
            assert!(reconcile_services(&sdk, "host", &[desired]).await.unwrap());
        }
    }

    #[cfg(feature = "test-support")]
    fn test_definition(host: &str) -> DetachedDpuServiceDefinition {
        let dpu = dpu_machine(0).id.to_string();
        let vpc = "00000000-0000-0000-0000-000000000001";
        DetachedDpuServiceDefinition {
            name: service_name(host, vpc, &dpu),
            namespace: NAMESPACE.into(),
            labels: ownership_labels(host, vpc, &dpu),
            owner_references: vec![OwnerReference {
                api_version: DEVICE_API_VERSION.into(),
                kind: "DPUDevice".into(),
                name: "device-device".into(),
                uid: "device-uid".into(),
                controller: Some(true),
                block_owner_deletion: Some(false),
            }],
            helm_chart: DetachedHelmChart {
                repo_url: "oci://repo".into(),
                chart: "unbound".into(),
                version: "1".into(),
                release_name: "unbound".into(),
                values: None,
            },
            deploy_in_cluster: Some(false),
            security: DetachedDpuServiceSecurity {
                privileged: false,
                spiffe: false,
            },
            service_daemon_set: Some(DetachedServiceDaemonSet {
                node_selector_labels: Some(BTreeMap::from([(DPU_LABEL.into(), dpu)])),
                ..Default::default()
            }),
            service_id: None,
            interfaces: None,
        }
    }

    #[cfg(feature = "test-support")]
    fn observation(definition: &DetachedDpuServiceDefinition) -> DpuServiceObservation {
        let mut observed = carbide_dpf::dpu_service_observation(definition);
        observed.uid = Some("service-uid".into());
        observed.resource_version = Some("7".into());
        observed
    }

    #[test]
    fn names_are_stable_bounded_and_include_every_identity() {
        let name = service_name("host", "vpc", "dpu");
        assert_eq!(name, service_name("host", "vpc", "dpu"));
        assert!(name.len() <= 53);
        for identity in [
            ("other", "vpc", "dpu"),
            ("host", "other", "dpu"),
            ("host", "vpc", "other"),
        ] {
            assert_ne!(name, service_name(identity.0, identity.1, identity.2));
        }
    }
}
