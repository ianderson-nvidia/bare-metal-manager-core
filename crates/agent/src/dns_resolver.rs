/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Persist and apply the DPU resolver's complete desired configuration.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use eyre::{Context, bail, ensure};
use hickory_resolver::proto::rr::Name;
use rpc::dns::DpuDnsConfig;
use tokio::process::Command;

use crate::agent_platform::ManagedFile;

const CONFIG_PATH: &str = "/var/lib/carbide/dns/unbound.conf";
const CONTROL_SOCKET: &str = "/run/carbide-dns/control.sock";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct DnsResolver {
    config_path: PathBuf,
    checkconf_binary: PathBuf,
    control_binary: PathBuf,
    applied_contents: Option<String>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from(CONFIG_PATH),
            checkconf_binary: PathBuf::from("/usr/sbin/unbound-checkconf"),
            control_binary: PathBuf::from("/usr/sbin/unbound-control"),
            applied_contents: None,
        }
    }
}

impl DnsResolver {
    /// Validate before replacing the persisted configuration, then retry runtime
    /// application until Unbound acknowledges it. A successful unchanged pass
    /// checks availability without clearing the resolver's cache.
    pub(super) async fn reconcile(&mut self, config: &DpuDnsConfig) -> eyre::Result<()> {
        let contents = render_config(config).context("render DNS resolver configuration")?;
        let directory = self
            .config_path
            .parent()
            .ok_or_else(|| eyre::eyre!("DNS resolver configuration has no parent directory"))
            .context("locate DNS resolver configuration directory")?;
        std::fs::create_dir_all(directory)
            .context("create DNS resolver configuration directory")?;
        let current_contents = match std::fs::read(&self.config_path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("read persisted DNS resolver configuration"),
        };

        if current_contents.as_deref() != Some(contents.as_bytes()) {
            // The candidate is never the startup configuration until the actual
            // Unbound parser accepts it. The shared directory mount sees the
            // atomic replacement performed by ManagedFile.
            let mut candidate = tempfile::NamedTempFile::new_in(directory)
                .context("create candidate DNS resolver configuration")?;
            candidate
                .write_all(contents.as_bytes())
                .context("write candidate DNS resolver configuration")?;
            run_command(&self.checkconf_binary, &[candidate.path()])
                .await
                .context("validate candidate DNS resolver configuration")?;
            ManagedFile::new(self.config_path.clone())
                .ensure_contents(contents.as_bytes())
                .context("persist DNS resolver configuration")?;
            self.applied_contents = None;
        }

        // Persist first so an independent Unbound restart loads the desired
        // rules. A missing startup socket or failed reload leaves this file in
        // place and keeps the apply pending for the next agent iteration.
        if self.applied_contents.as_deref() != Some(contents.as_str()) {
            std::fs::File::open(directory)
                .context("open DNS resolver configuration directory")?
                .sync_all()
                .context("persist DNS resolver configuration rename")?;
            self.control("reload")
                .await
                .context("reload DNS resolver configuration")?;
        }
        if let Err(error) = self.control("status").await {
            self.applied_contents = None;
            return Err(error).context("check DNS resolver availability");
        }
        self.applied_contents = Some(contents);
        Ok(())
    }

    async fn control(&self, operation: &str) -> eyre::Result<()> {
        run_command(
            &self.control_binary,
            &[
                Path::new("-c"),
                &self.config_path,
                Path::new("-s"),
                Path::new(CONTROL_SOCKET),
                Path::new(operation),
            ],
        )
        .await
        .context("run DNS resolver control command")
    }
}

async fn run_command(binary: &Path, arguments: &[&Path]) -> eyre::Result<()> {
    let output = tokio::time::timeout(
        COMMAND_TIMEOUT,
        Command::new(binary)
            .args(arguments)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("wait for DNS resolver command")?
    .context("execute DNS resolver command")?;
    if !output.status.success() {
        bail!(
            "{} exits with {}: {}{}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

fn render_config(config: &DpuDnsConfig) -> eyre::Result<String> {
    let authoritative_servers = parse_servers(&config.authoritative_servers)
        .context("validate authoritative DNS servers")?;
    let recursive_servers =
        parse_servers(&config.recursive_servers).context("validate recursive DNS servers")?;
    let mut zones = BTreeSet::new();
    for zone in &config.authoritative_zones {
        // DNS presentation names can contain configuration syntax. These zones
        // use plain ASCII labels; reject escaping, quotes, and whitespace before
        // passing the name through the DNS wire-format length checks.
        ensure!(
            !zone.is_empty()
                && zone
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
            "authoritative DNS zone contains unsupported characters"
        );
        let name = Name::from_ascii(zone).context("parse authoritative DNS zone")?;
        ensure!(
            !name.is_root(),
            "the DNS root cannot be an authoritative zone"
        );
        let mut normalized = name.to_ascii().to_ascii_lowercase();
        if !normalized.ends_with('.') {
            normalized.push('.');
        }
        ensure!(
            normalized != "in-addr.arpa."
                && !normalized.ends_with(".in-addr.arpa.")
                && normalized != "ip6.arpa."
                && !normalized.ends_with(".ip6.arpa."),
            "reverse DNS zones are not supported by the DPU resolver"
        );
        zones.insert(normalized);
    }

    // Upstream traffic uses the pod's ordinary route and source address. Only
    // downstream replies use the FMDS link-local address and its policy route.
    // DNSSEC validation for forwarded queries belongs to the configured
    // recursive upstreams. Send complete query names to Carbide's authority.
    let mut contents = String::from(concat!(
        "# Managed by dpu-agent. Changes are replaced on reconciliation.\n",
        "server:\n",
        "    interface: 169.254.169.254\n",
        "    port: 53\n",
        "    ip-freebind: yes\n",
        "    do-udp: yes\n",
        "    do-tcp: yes\n",
        "    access-control: 0.0.0.0/0 allow\n",
        "    chroot: \"\"\n",
        "    username: \"\"\n",
        "    directory: \"/\"\n",
        "    pidfile: \"\"\n",
        "    do-daemonize: no\n",
        "    use-syslog: no\n",
        "    logfile: \"\"\n",
        "    module-config: \"iterator\"\n",
        "    qname-minimisation: no\n",
        "    serve-expired: no\n",
    ));
    // Unbound's built-in local zones, such as test., answer before stub
    // processing. Let queries for managed zones reach Carbide's authority.
    for zone in &zones {
        contents.push_str(&format!("    local-zone: \"{zone}\" transparent\n"));
    }
    contents.push_str(concat!(
        "remote-control:\n",
        "    control-enable: yes\n",
        "    control-use-cert: no\n",
    ));
    contents.push_str(&format!("    control-interface: {CONTROL_SOCKET}\n"));
    contents.push_str("forward-zone:\n    name: \".\"\n    forward-first: no\n");
    for address in recursive_servers {
        contents.push_str(&format!("    forward-addr: {address}\n"));
    }
    for zone in zones {
        contents.push_str(&format!(
            "stub-zone:\n    name: \"{zone}\"\n    stub-prime: no\n    stub-first: no\n"
        ));
        for address in &authoritative_servers {
            contents.push_str(&format!("    stub-addr: {address}\n"));
        }
    }
    Ok(contents)
}

fn parse_servers(servers: &[String]) -> eyre::Result<BTreeSet<IpAddr>> {
    ensure!(!servers.is_empty(), "DNS server list must not be empty");
    servers
        .iter()
        .map(|server| {
            let address: IpAddr = server.parse().context("parse DNS server IP address")?;
            let address = address.to_canonical();
            ensure!(
                !address.is_unspecified()
                    && !address.is_multicast()
                    && !address.is_loopback()
                    && address != IpAddr::V4(Ipv4Addr::BROADCAST)
                    && address != IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                "DNS server must be a reachable unicast upstream address"
            );
            Ok(address)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DpuDnsConfig {
        DpuDnsConfig {
            authoritative_servers: vec!["192.0.2.53".to_string()],
            recursive_servers: vec!["192.0.2.54".to_string()],
            authoritative_zones: vec!["machines.example.".to_string()],
        }
    }

    fn resolver(directory: &Path) -> DnsResolver {
        DnsResolver {
            config_path: directory.join("unbound.conf"),
            checkconf_binary: PathBuf::from("/bin/true"),
            control_binary: PathBuf::from("/bin/true"),
            applied_contents: None,
        }
    }

    fn temporary_directory() -> tempfile::TempDir {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp");
        std::fs::create_dir_all(&root).expect("create project temporary directory");
        tempfile::tempdir_in(root).expect("create resolver test directory")
    }

    #[test]
    fn render_deterministic_forward_and_stub_configuration() {
        let mut input = config();
        input.authoritative_zones = vec![
            "ZONES.example".to_string(),
            "machines.example.".to_string(),
            "zones.example.".to_string(),
        ];
        input.recursive_servers.push("2001:db8::53".to_string());
        let expected = render_config(&input).expect("valid resolver configuration");
        input.authoritative_zones.reverse();
        input.recursive_servers.reverse();
        assert_eq!(
            render_config(&input).expect("valid resolver configuration"),
            expected
        );
        assert_eq!(expected.matches("name: \"zones.example.\"").count(), 1);
        assert!(expected.contains("forward-addr: 2001:db8::53"));
        assert!(expected.contains("stub-addr: 192.0.2.53"));
        assert!(expected.contains("stub-prime: no\n    stub-first: no"));

        input.authoritative_zones.clear();
        let cleared = render_config(&input).expect("an empty zone snapshot is valid");
        assert!(!cleared.contains("stub-zone:"));
        assert!(!cleared.contains("local-zone:"));
        assert!(cleared.contains("forward-zone:"));
    }

    #[test]
    fn managed_private_zone_overrides_unbound_local_defaults() {
        let mut input = config();
        input.authoritative_zones = vec!["machines.test.".to_string()];
        let rendered = render_config(&input).expect("valid private zone configuration");
        let (server, _) = rendered
            .split_once("remote-control:")
            .expect("remote control follows server configuration");
        assert!(server.contains("local-zone: \"machines.test.\" transparent\n"));
        assert!(rendered.contains("stub-zone:\n    name: \"machines.test.\"\n"));
    }

    #[test]
    fn reject_unsafe_or_unsupported_zones() {
        use carbide_test_support::Outcome::Fails;
        use carbide_test_support::scenarios;

        scenarios!(run = |zone: &str| {
            let mut input = config();
            input.authoritative_zones = vec![zone.to_string()];
            render_config(&input).map_err(drop)
        };
            "unsupported authority" {
                "." => Fails,
                "10.in-addr.arpa." => Fails,
                "ip6.arpa." => Fails,
            }
            "configuration injection" {
                "example.\"\nserver:\n    interface: 0.0.0.0" => Fails,
            }
            "invalid DNS name" {
                "machines..example." => Fails,
            }
        );
    }

    #[test]
    fn reject_missing_or_unusable_upstreams() {
        use carbide_test_support::Outcome::Fails;
        use carbide_test_support::scenarios;

        scenarios!(run = |servers: &[&str]| {
            let servers: Vec<String> = servers.iter().map(|server| server.to_string()).collect();
            parse_servers(&servers).map_err(drop)
        };
            "required reachable upstream" {
                [].as_slice() => Fails,
                ["0.0.0.0"].as_slice() => Fails,
                ["::1"].as_slice() => Fails,
                ["224.0.0.53"].as_slice() => Fails,
                ["255.255.255.255"].as_slice() => Fails,
            }
            "self forwarding loop" {
                ["169.254.169.254"].as_slice() => Fails,
                ["::ffff:169.254.169.254"].as_slice() => Fails,
            }
            "configuration injection" {
                ["192.0.2.53\nserver:"].as_slice() => Fails,
            }
        );
    }

    #[tokio::test]
    async fn rejected_candidate_preserves_persisted_configuration() {
        let directory = temporary_directory();
        let mut resolver = resolver(directory.path());
        let mut input = config();
        resolver
            .reconcile(&input)
            .await
            .expect("initial configuration applies");
        let previous = std::fs::read(&resolver.config_path).expect("read initial configuration");

        input.authoritative_zones.push("new.example.".to_string());
        resolver.checkconf_binary = PathBuf::from("/bin/false");
        assert!(resolver.reconcile(&input).await.is_err());
        assert_eq!(
            std::fs::read(&resolver.config_path).expect("read retained configuration"),
            previous
        );
    }

    #[tokio::test]
    async fn failed_reload_retries_persisted_configuration_and_checks_availability() {
        let directory = temporary_directory();
        let mut resolver = resolver(directory.path());
        let input = config();
        resolver.control_binary = PathBuf::from("/bin/false");
        assert_eq!(
            resolver
                .reconcile(&input)
                .await
                .expect_err("injected reload failure")
                .to_string(),
            "reload DNS resolver configuration"
        );
        assert_eq!(
            std::fs::read_to_string(&resolver.config_path)
                .expect("configuration survives reload failure"),
            render_config(&input).expect("valid resolver configuration")
        );
        assert!(resolver.applied_contents.is_none());

        // The unchanged on-disk file must not suppress retrying the failed
        // runtime apply. It also must not require validating the same bytes again.
        resolver.checkconf_binary = PathBuf::from("/bin/false");
        assert_eq!(
            resolver
                .reconcile(&input)
                .await
                .expect_err("unchanged configuration retries reload")
                .to_string(),
            "reload DNS resolver configuration"
        );
        resolver.control_binary = PathBuf::from("/bin/true");
        resolver
            .reconcile(&input)
            .await
            .expect("retry applies persisted configuration");
        assert!(resolver.applied_contents.is_some());

        resolver.control_binary = PathBuf::from("/bin/false");
        assert_eq!(
            resolver
                .reconcile(&input)
                .await
                .expect_err("unchanged configuration still checks availability")
                .to_string(),
            "check DNS resolver availability"
        );
        assert!(resolver.applied_contents.is_none());
    }
}
