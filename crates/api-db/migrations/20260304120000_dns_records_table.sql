-- Create an optional relationship between domains and tenants.
-- For tenant-scoped zones, this allows us to enforce that the domain is owned by a tenant.
-- It also allows us to query for all domains owned by a tenant, (or vpc through tenant table)
-- For intrastructure zones (e.g. `adm.$SITE`, bmc.$SITE), the tenant_organization_id will be NULL.
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS tenant_organization_id VARCHAR(64),
    ADD CONSTRAINT domains_organization_id_fkey FOREIGN KEY(tenant_organization_id) REFERENCES tenants(organization_id)
;

-- Create the `records` table to hold DNS records for all zones.  This is a more
-- traditional DNS schema than the existing view-based approach and will allow us
-- to support arbitrary record types and names in the future.
-- The `records` table has the following columns:
--
-- `id` is a unique identifier for each record.
-- `name` is the FQDN of the record, stored in lowercase without a trailing dot (e.g. `machine-id.adm.<site>.<domain>`).
-- `domain_id` is a foreign key to the `domains` table, indicating which zone the record belongs to.
-- `type` is the DNS record type (e.g. A, AAAA, CNAME, NS, etc.).
-- `content` is the record content (e.g. IP address for A/AAAA, target domain for CNAME, etc.).
-- `ttl` is the time-to-live for the record, in seconds.  Should default to zone TTL
-- `prio` is the priority for MX and SRV records; NULL for other record types.
-- The CHECK constraint enforces the lowercase invariant at insert/update time.
CREATE TABLE records (
    id          BIGSERIAL PRIMARY KEY,
    domain_id   UUID NOT NULL,
    name        TEXT NOT NULL,
    type        VARCHAR(10) NOT NULL,
    content     TEXT NOT NULL,
    ttl         INT NOT NULL,
    prio        INT DEFAULT NULL,
    ordername   TEXT,
    CONSTRAINT domain_exists
        FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    CONSTRAINT c_lowercase_name
        CHECK (name IS NULL OR name = lower(name))
);

CREATE INDEX records_name_idx      ON records (name);
CREATE INDEX records_domain_id_idx ON records (domain_id);
