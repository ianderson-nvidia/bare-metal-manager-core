# Per-service container specifications.
#
# Every image carbide publishes starts from the same base: a distroless root
# with one binary in /bin. Most services need nothing more. The ones that do —
# a shell to exec, a directory that must exist before startup, a legacy path
# some PodSpec still references — declare those needs here, one entry per
# service, and flake.nix feeds them to mkContainer.
#
# This file holds data, not derivations, and takes no package set. The builders
# live in flake.nix so that they can share one crane `cargoArtifacts` across
# every binary; splitting them per-service would rebuild the dependency closure
# once per image. What that buys here is a file describing *what* each service
# needs, readable without knowing how any of it is assembled.
#
# FIELDS — all optional; an absent field means the service doesn't need it.
#
#   runtime           Packages placed on the image's PATH. A function of the
#                     package set rather than a plain list, because the same
#                     entry builds both the amd64 image (against `pkgs`) and
#                     the arm64 one (against `aarch64CrossPkgs`); a list would
#                     bake in whichever architecture evaluated first.
#   extraCommands     Shell run at image build time, from the image root.
#   optCarbideAliases /opt/carbide/<alias> -> /bin/<target> symlinks.
#   optCarbideDirs    Empty directories created under /opt/carbide/.
#   entrypoint        OCI Entrypoint. Set only on images that run standalone.
#                     Server-side images omit it so k8s PodSpecs stay in charge
#                     of what runs.
#   cmd               OCI Cmd, for images whose default process is not their
#                     entrypoint. See machine-validation-config.
#
# Every service that produces a container has an entry, including the many
# that need nothing beyond their binary and so are written `{ }`. flake.nix
# rejects a service missing from this file and an entry matching no service,
# which makes the list below the inventory of what carbide ships — an empty
# entry is a deliberate statement that the plain distroless image is correct,
# not an oversight.
{
  # aarch64 Mellanox Firmware Tools. The DPU agent shells out to flint and
  # mlxfwreset for firmware operations.
  mftAarch64,
  # Custom OpenTelemetry collector build; supplies the wrapper scripts that
  # become the otelcol image's entrypoint.
  otelcolContribAarch64,
  # Scripts and firmware staged for the nvswitch-manager image.
  nsmStaticFiles,
}:

{
  # ==========================================================================
  # Server-side services — built for both amd64 and arm64
  # ==========================================================================

  carbide-api = {
    # The API drives hardware directly: tpm2-tools for attestation, ipmitool
    # for out-of-band power control, iproute2/iputils for reachability checks.
    runtime =
      p: with p; [
        tpm2-tools
        ipmitool
        busybox
        iputils
        iproute2
      ];
    # Mount points. Init containers populate these before the API starts, and
    # the mounts fail if the directories are missing.
    optCarbideDirs = [
      "pxe/templates"
      "migrations"
      "static"
      "firmware"
    ];
  };

  carbide-dns.runtime = p: with p; [ busybox ];

  carbide-pxe.runtime = p: with p; [ busybox ];

  carbide-dhcp = {
    # The image ships Kea itself, since carbide-dhcp is a hook library loaded
    # into kea-dhcp4-server rather than a standalone program.
    runtime =
      p: with p; [
        kea
        busybox
      ];
    extraCommands = "mkdir -p var/run/kea";
  };

  nico-admin-cli = {
    # Kept until every PodSpec referencing the pre-rename binaries is updated.
    optCarbideAliases = [
      {
        alias = "forge-admin-cli";
        target = "nico-admin-cli";
      }
      {
        alias = "carbide-admin-cli";
        target = "nico-admin-cli";
      }
    ];
  };

  # These reach the outside world only over the network, and their PodSpecs
  # supply the command, so the binary alone is the whole image.
  carbide-bmc-proxy = { };
  carbide-dsx-exchange-consumer = { };
  carbide-health = { };
  carbide-log-parser = { };
  carbide-ssh-console = { };

  # Runs inside the scout initramfs as well as in a container. The initramfs
  # copy is a .deb built from the same binary (see nix/deb/debs.nix), and that
  # is where its runtime tools — tpm2-tools, ipmitool — are bundled.
  carbide-scout = { };

  # ==========================================================================
  # DPU-side services — arm64 only
  # ==========================================================================

  forge-dpu-agent = {
    # python3 and bash back the agent's provisioning scripts; cri-tools and
    # lldpd let it inspect the container runtime and link topology.
    runtime =
      p:
      [ mftAarch64 ]
      ++ (with p; [
        bash
        python3
        iproute2
        lldpd
        cri-tools
        busybox
      ]);
    entrypoint = [ "/bin/forge-dpu-agent" ];
  };

  forge-dhcp-server = {
    runtime =
      p: with p; [
        kea
        busybox
      ];
    # The DPU's service definition invokes the binary through /var/support,
    # so the image provides that path as a symlink onto /bin.
    extraCommands = ''
      mkdir -p var/run/kea
      mkdir -p var/support/forge-dhcp/bin
      ln -sf /bin/forge-dhcp-server var/support/forge-dhcp/bin/forge-dhcp-server
    '';
    entrypoint = [ "/var/support/forge-dhcp/bin/forge-dhcp-server" ];
  };

  carbide-fmds = {
    runtime = p: with p; [ busybox ];
    entrypoint = [ "/bin/carbide-fmds" ];
  };

  transceiver-exporter.entrypoint = [ "/usr/bin/transceiver-exporter" ];

  otelcol-contrib = {
    # The wrapper assembles a config from fragments at startup, so the image
    # needs a shell alongside the collector binary.
    runtime =
      p:
      [ otelcolContribAarch64.passthru.wrapperScripts ]
      ++ (with p; [
        bash
        busybox
      ]);
    entrypoint = [ "/etc/otelcol-contrib/otelcol-wrapper" ];
  };

  # ==========================================================================
  # rest-api services
  # ==========================================================================

  # Staged under /opt/nvswitch-manager to match the working directory the
  # service resolves its scripts and firmware against.
  rest-api-nsm.runtime = _: [ nsmStaticFiles ];

  # nsm is the exception in this set: it manages switch hardware and needs its
  # scripts and firmware on disk. The rest are Go services that talk to the
  # database and each other over the network and need nothing on the image.
  rest-api-api = { };
  rest-api-credsmgr = { };
  rest-api-flow = { };
  rest-api-mcp = { };
  rest-api-migrations = { };
  rest-api-nicocli = { };
  rest-api-psm = { };
  rest-api-site-agent = { };
  rest-api-sitemgr = { };
  rest-api-workflow = { };

  # ==========================================================================
  # Tooling and static-content images
  # ==========================================================================

  machine-a-tron = {
    # cacert for TLS to the BMCs it mocks; libssl and libudev arrive through
    # the binary's RPATH closure rather than being named here.
    runtime =
      p: with p; [
        cacert
        iproute2
        iputils
        busybox
      ];
    # Callers invoke it by its /opt path. Symlinked rather than copied so the
    # binary exists at exactly one location in the image.
    extraCommands = ''
      mkdir -p opt/machine-a-tron/bin
      ln -sf /bin/machine-a-tron opt/machine-a-tron/bin/machine-a-tron
      mkdir -p tmp/machine-a-tron-data
    '';
    entrypoint = [ "/opt/machine-a-tron/bin/machine-a-tron" ];
  };

  boot-artifacts-x86-64 = {
    # Carries the PXE blobs and nothing else. nico-pxe runs it as an init
    # container that copies /x86_64 into a shared volume, so the image needs a
    # shell for that `cp` and something to keep it alive while the copy runs.
    runtime =
      p: with p; [
        bash
        coreutils
      ];
    cmd = [
      "/bin/bash"
      "-c"
      "trap : TERM INT; sleep 9999999999d & wait"
    ];
  };

  machine-validation-runner = {
    # bash runs the validation scripts; coreutils supplies a sleep that accepts
    # the `d` suffix those scripts use.
    runtime =
      p: with p; [
        bash
        coreutils
      ];
  };

  machine-validation-config = {
    runtime =
      p: with p; [
        bash
        coreutils
      ];
    # This image carries no program — it exists so other containers can mount
    # its config tree. The keep-alive holds it running for as long as they need
    # it, and trapping TERM/INT keeps shutdown prompt. Declared as cmd rather
    # than entrypoint so a caller can replace it to inspect the image.
    cmd = [
      "/bin/bash"
      "-c"
      "trap : TERM INT; sleep 9999999999d & wait"
    ];
  };
}
