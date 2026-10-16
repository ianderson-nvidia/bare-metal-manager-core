# FMDS DPU DNS Resolver

The optional Unbound sidecar provides caching DNS on the IPv4 address
`169.254.169.254`, using UDP and TCP port 53. It shares the FMDS pod network
namespace. The DPU agent maintains its configuration through shared host
directories and reloads zone changes without restarting either container.

## Enable the Resolver

Deploy the updated NICo API, DPU agent, and FMDS images together with both
updated Helm charts. The agent image requires the Unbound validation and
control utilities; the FMDS image supplies the Unbound server. Initial
enablement changes the pods through the existing DPF rollout process.

For a site with DPF enabled, add the following section to the NICo API
configuration. Replace the documentation addresses with reachable site
endpoints.

```toml
[dpf.dns]
authoritative_servers = ["192.0.2.53", "192.0.2.54"]
recursive_servers = ["198.51.100.53", "198.51.100.54"]
```

Both lists are required and must contain at least one IPv4 or IPv6 address
literal without an explicit port. Every endpoint uses UDP and TCP port 53.
Unspecified, loopback, multicast, broadcast, and `169.254.169.254` addresses
are rejected. Unbound manages upstream selection.

The `authoritative_servers` must serve Carbide's authoritative DNS data. The
`recursive_servers` resolve names outside those zones. Both groups must be
reachable through the FMDS pod's ordinary network, including UDP and TCP
port 53.

Both charts default `dnsResolver.enabled` to `false`. During DPF deployment,
NICo sets this value in both charts according to the presence of `[dpf.dns]`.
This API-owned setting overrides per-service extra Helm values. Omitting
`[dpf.dns]` disables the feature; the resulting chart rollout removes the
Unbound sidecar and disables agent reconciliation. It retains existing
configuration files on the DPU host.

## Zone Configuration and Recovery

On each configuration poll, the API supplies the complete set of live
infrastructure forward zones that Carbide serves. The agent sorts and
deduplicates the configuration, creates authoritative stub zones, and forwards
other names to the recursive upstreams. An empty zone set removes all stubs
and keeps default forwarding. Zone additions and removals reconcile
independently of network configuration versions.

The agent writes `/var/lib/carbide/dns/unbound.conf` after validating a
candidate with Unbound. It replaces the file atomically, persists the change,
and requests a reload through `/run/carbide-dns/control.sock`. Both charts
mount these host directories; Unbound mounts the configuration directory
read-only. Directory mounts expose replacements to the running container.

A reload clears the DNS cache. Unchanged configuration only checks resolver
availability. Invalid candidates preserve the previous file. If runtime
application fails, the agent keeps the validated file and retries on a later
iteration. The agent reports DNS errors in its network configuration status.
Use the agent logs to check for DNS application errors. Agent readiness stays
true after its first successful configuration. The sidecar readiness probe
checks resolver availability.

The sidecar waits for the first configuration file before starting. After a
container restart, Unbound reads the persisted file. After DPU reprovisioning
removes local files, the agent regenerates the configuration from the API.
If an enabled agent receives no DNS configuration, it reports an error and
retains the previous file. Initial agent readiness waits for successful DNS
configuration along with the other enabled services.

## Network Requirements

The resolver provides one shared infrastructure DNS view. Managed zone names
use ASCII letters, digits, hyphens, underscores, and dots; the agent rejects
invalid DNS names and configuration syntax.

The listener uses the existing FMDS address and tenant physical-interface
route. Verify reachability from the intended client interface. Configure
clients to use `169.254.169.254`.

Unbound uses its iterator module for caching and forwarding. Choose recursive
upstreams that perform DNSSEC validation when required.
