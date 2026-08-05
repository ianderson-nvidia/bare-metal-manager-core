# Nix builds and lints.
#
#   just              list every recipe
#   just list         list every target the flake exposes
#   just container carbide-api
#   just lint-ci      the full lint suite
#
# Recipes that produce artifacts other tasks consume leave them behind a
# `result-*` symlink at the repo root. Those names are read literally by the
# staging tasks in pxe/Makefile.toml, so renaming one means renaming both.
#
# Nix supplies every toolchain these recipes need, including the pinned
# nightly used for rustfmt and the carbide-lints rustc driver. Nothing here
# depends on the build containers in dev/docker/, and nothing needs rustup.

# Run a command in the dev shell, unless we are already inside one. Recipes
# use this rather than assuming the caller ran `nix develop` first, so that
# `just lint-ci` works from a bare shell and does not pay for a nested shell
# when it doesn't have to.
dev := if env_var_or_default("IN_NIX_SHELL", "") == "" { "nix develop --command" } else { "" }

# Show the available recipes.
default:
    @just --list --unsorted

# Fail with install instructions if the nix CLI is unavailable.
[private]
_check-nix:
    #!/usr/bin/env bash
    command -v nix >/dev/null 2>&1 || {
        echo "error: nix not found on PATH."
        echo
        echo "Install with the Determinate Systems installer, which enables flakes"
        echo "and the FlakeHub binary cache out of the box:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install"
        exit 1
    }

# List every Nix build target (containers, debs, binaries, iPXE).
list: _check-nix
    nix flake show

# ==============================================================================
# Containers
# ==============================================================================

# Build one amd64 service container, e.g. `just container carbide-api`.
container service: _check-nix
    nix build ".#{{ service }}-container" -o "result-{{ service }}-container"
    @echo "Built: result-{{ service }}-container"

# Build one arm64 service container, e.g. `just container-arm64 forge-dpu-agent`.
container-arm64 service: _check-nix
    nix build ".#{{ service }}-container-arm64" -o "result-{{ service }}-container-arm64"
    @echo "Built: result-{{ service }}-container-arm64"

# Build an amd64 service container and load it into the local Docker daemon.
container-load service: _check-nix
    nix run ".#{{ service }}-container-copy-to-docker"

# Build every amd64 carbide service container.
containers-carbide: _check-nix
    nix build --no-link --print-out-paths \
      .#carbide-api-container \
      .#carbide-bmc-proxy-container \
      .#carbide-dhcp-container \
      .#carbide-dns-container \
      .#carbide-dsx-exchange-consumer-container \
      .#carbide-health-container \
      .#carbide-log-parser-container \
      .#carbide-pxe-container \
      .#carbide-scout-container \
      .#carbide-ssh-console-container \
      .#nico-admin-cli-container

# Build every arm64 carbide service container (cross-compiled).
containers-carbide-arm64: _check-nix
    nix build --no-link --print-out-paths \
      .#carbide-api-container-arm64 \
      .#carbide-dhcp-container-arm64 \
      .#carbide-dns-container-arm64 \
      .#carbide-dsx-exchange-consumer-container-arm64 \
      .#carbide-health-container-arm64 \
      .#carbide-pxe-container-arm64 \
      .#carbide-scout-container-arm64 \
      .#carbide-ssh-console-container-arm64 \
      .#nico-admin-cli-container-arm64

# Build every DPU-side arm64 container (cross-compiled from x86).
containers-dpu: _check-nix
    nix build --no-link --print-out-paths \
      .#carbide-fmds-container-arm64 \
      .#forge-dhcp-server-container-arm64 \
      .#forge-dpu-agent-container-arm64 \
      .#otelcol-contrib-container-arm64 \
      .#transceiver-exporter-container-arm64

# Build every amd64 rest-api service container.
containers-rest-api: _check-nix
    nix build --no-link --print-out-paths \
      .#rest-api-api-container \
      .#rest-api-credsmgr-container \
      .#rest-api-flow-container \
      .#rest-api-mcp-container \
      .#rest-api-migrations-container \
      .#rest-api-nicocli-container \
      .#rest-api-nsm-container \
      .#rest-api-psm-container \
      .#rest-api-site-agent-container \
      .#rest-api-sitemgr-container \
      .#rest-api-workflow-container

# Build every arm64 rest-api service container (cross-compiled).
containers-rest-api-arm64: _check-nix
    nix build --no-link --print-out-paths \
      .#rest-api-api-container-arm64 \
      .#rest-api-credsmgr-container-arm64 \
      .#rest-api-flow-container-arm64 \
      .#rest-api-mcp-container-arm64 \
      .#rest-api-migrations-container-arm64 \
      .#rest-api-nicocli-container-arm64 \
      .#rest-api-nsm-container-arm64 \
      .#rest-api-psm-container-arm64 \
      .#rest-api-site-agent-container-arm64 \
      .#rest-api-sitemgr-container-arm64 \
      .#rest-api-workflow-container-arm64

# Build the hardware-simulation and machine-validation containers.
containers-validation: _check-nix
    nix build --no-link --print-out-paths \
      .#machine-a-tron-container \
      .#machine-validation-config-container \
      .#machine-validation-config-container-arm64 \
      .#machine-validation-runner-container

# ==============================================================================
# Boot artifacts and packages
# ==============================================================================

# Build the forge-scout Debian packages for amd64 and arm64.
deb-scout: _check-nix
    nix build .#forge-scout-deb       -o result-forge-scout-deb-amd64
    nix build .#forge-scout-deb-arm64 -o result-forge-scout-deb-arm64
    @echo "Built:"
    @echo "  result-forge-scout-deb-amd64/"
    @echo "  result-forge-scout-deb-arm64/"

# Build the iPXE EFI bootloaders for x86_64 and aarch64.
ipxe: _check-nix
    nix build .#ipxe-efi-x86     -o result-ipxe-efi-x86
    nix build .#ipxe-efi-aarch64 -o result-ipxe-efi-aarch64
    @echo "Built:"
    @echo "  result-ipxe-efi-x86/"
    @echo "  result-ipxe-efi-aarch64/"

# Assembling a PXE boot image or a BFB takes two steps. This recipe is step
# one: it compiles the pieces and leaves each behind a `result-*` symlink.
# Step two copies them into the static webroot and assembles the image:
#
#   just boot-inputs
#   cargo make --cwd pxe build-boot-artifacts-x86-host-from-nix
#
# Build every PXE boot input: iPXE bootloaders, scout .debs, aarch64 scout.
boot-inputs: _check-nix ipxe deb-scout
    nix build .#carbide-scout-aarch64 -o result-carbide-scout-aarch64
    @echo "Built:"
    @echo "  result-ipxe-efi-x86/          result-ipxe-efi-aarch64/"
    @echo "  result-forge-scout-deb-amd64/ result-forge-scout-deb-arm64/"
    @echo "  result-carbide-scout-aarch64/"

# scout ships as three files that have to travel together: the kernel, its
# initrd, and the command line naming which system to activate. Stage them
# into the webroot with:
#
# cargo make --cwd pxe scout-x86_64-from-nix
#
# Build both halves of scout: the loader, and the system the loader kexecs into.
scout: _check-nix
    nix build .#scout-loader -o result-scout-loader
    nix build .#scout-kexec  -o result-scout-kexec
    @echo "loader:  $(stat -c %s result-scout-loader/scout-loader.efi | numfmt --to=iec)"
    @cat result-scout-kexec/sizes.txt

# Unlike scout this is a single self-contained UKI: iPXE chains it directly, so
# there is no loader stage and nothing to fetch at boot. Stage it with:
#
# cargo make --cwd pxe qcow-imager-x86_64-from-nix
#
# Build the qcow imager, which writes a customer image onto local disk.
qcow-imager: _check-nix
    nix build .#qcow-imager -o result-qcow-imager
    @echo "qcow-imager: $(stat -c %s result-qcow-imager/qcow-imager.efi | numfmt --to=iec)"

# ==============================================================================
# aarch64 boot images
#
# One recipe, because Nix already does the host-appropriate thing. These are
# ordinary `aarch64-linux` derivations, so the daemon realises them whichever
# way it can: natively on an aarch64 runner, under binfmt/qemu on an x86 box,
# or offloaded to a remote builder if one is configured
# (docs/nix-aarch64-builder-setup.md). Nothing here has to detect the host.
#
# On x86 this needs `extra-platforms = aarch64-linux` in nix.conf, or a
# builder. Without either it fails with "platform mismatch" rather than
# falling back — deliberately, since a silent fallback to cross-compiling
# would produce different store paths on different machines.
#
# What that buys is cache hits. nixpkgs' Hydra builds aarch64 natively, so
# these are the paths that exist in cache.nixos.org — the kernel, glibc, gcc
# and systemd all arrive prebuilt, and only carbide's own packages are built
# locally. Emulation is therefore far cheaper than the usual 5-20x figure
# suggests: the expensive things are downloaded, not emulated.
# ==============================================================================

# Build an aarch64 image, e.g. `just image-aarch64 qcow-imager`.
image-aarch64 name: _check-nix
    nix build ".#packages.aarch64-linux.{{ name }}-aarch64" -o "result-{{ name }}-aarch64"

# Escape hatch, not an alternative. Cross-compiling produces *different store
# paths* — nobody upstream has ever built them, so nothing substitutes and the
# whole aarch64 world compiles from source on every empty store. It earns its
# keep in exactly two cases: no aarch64 execution available at all (no qemu,
# no builder), or a compile-bound image on a machine with many x86 cores,
# where native-speed compilation beats emulated compilation.
#
# Do not reach for this to "fix" a failing image-aarch64 — a silent switch
# between the two is what fragments the cache.
#
# Build an aarch64 image by cross-compiling from this host.
image-aarch64-cross name: _check-nix
    nix build ".#{{ name }}-aarch64" -o "result-{{ name }}-aarch64"

# Replaces dev/docker/Dockerfile.release-artifacts-x86_64, which COPYs whatever
# happens to be staged in pxe/static/blobs/internal. This is assembled from the
# derivations instead, so the image cannot pick up a stale artifact.
#
# Build the boot-artifacts container: iPXE, scout loader and rootfs, and cache.
boot-artifacts: _check-nix
    nix build .#boot-artifacts-x86-64-container -o result-boot-artifacts

# ==============================================================================
# Compliance
# ==============================================================================

# Generate CycloneDX/SPDX/CSV SBOMs for a container, for nSpect upload.
sbom service: _check-nix
    nix run ".#sbom-{{ service }}-container"

# ==============================================================================
# Lints and tests
#
# `lint-ci` is the whole suite, in the order the lint-police CI job runs it.
# taplo is deliberately absent: CI runs it advisorily (`taplo fmt --check ||
# echo ...`), so making it a hard dependency here would be stricter than the
# behaviour this replaces.
# ==============================================================================

# Builds every aarch64 binary, so it is slower than the lints and is kept out
# of `lint-ci` for that reason. It replaces the cargo-make task
# check-aarch64-release-container-services-page-size, which only inspected
# whatever a previous cargo build had left in target/.
#
# Run the flake's checks: aarch64 binaries must map on a 64KB-page kernel.
flake-check: _check-nix
    nix flake check

# Run the full lint suite. Mirrors the lint-police CI job.
lint-ci: clippy carbide-lints lint-error-messages check-format check-workspace-deps check-event-names check-metric-docs check-licenses check-bans

# Run the clippy code linter.
clippy: _check-nix
    {{ dev }} cargo clippy --locked --all-targets --all-features

# Run the custom lints defined in lints/carbide-lints.
carbide-lints: _setup-carbide-lints
    # The driver links against librustc_driver from the nightly toolchain and
    # has to find it at run time. rustup normally handles this with a shim; the
    # dev shell has no rustup, so point the loader at the nightly lib dir.
    #
    # No --all-features: it enables `test_support`, which disables the
    # txn_held_across_await lint. No --all-targets: test targets are not linted.
    {{ dev }} bash -c 'export LD_LIBRARY_PATH="$(dirname "$(dirname "$CARGO_NIGHTLY")")/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; cargo carbide-lints'

# Build and install the `cargo carbide-lints` subcommand.
[private]
_setup-carbide-lints: _check-nix
    # carbide-lints is a rustc driver, so nightly rustc must compile it. cargo
    # resolves rustc from PATH and the dev shell puts the stable toolchain
    # first — which has no rustc-dev, so the rustc_* imports fail to resolve.
    # RUSTC_WRAPPER is cleared because sccache cannot handle rustc-private.
    {{ dev }} bash -c 'cd lints/carbide-lints && RUSTC="$(dirname "$CARGO_NIGHTLY")/rustc" RUSTC_WRAPPER= "$CARGO_NIGHTLY" install --path .'

# Check that error messages follow C-GOOD-ERR (lowercase, no trailing period).
lint-error-messages: _check-nix
    @{{ dev }} cargo --quiet xtask lint-error-messages || (RC=$?; echo 'To fix automatically, run `cargo xtask lint-error-messages --fix`'; exit $RC)

# Check formatting. RUSTFMT points at the pinned nightly, which sorts imports.
check-format: _check-nix
    {{ dev }} cargo fmt --all -- --check

# Reformat with the pinned nightly rustfmt.
format: _check-nix
    {{ dev }} cargo fmt --all

# Check for dependency versions declared in crates instead of the workspace root.
check-workspace-deps: _check-nix
    @{{ dev }} cargo --quiet xtask check-workspace-deps || (RC=$?; echo 'To fix automatically, run `cargo xtask check-workspace-deps --fix`'; exit $RC)

# Check that production instrumented Events have unique event_name identities.
check-event-names: _check-nix
    {{ dev }} cargo --quiet xtask check-event-names

# Fail if a #[derive(Event)] counter/histogram has no row in docs/observability/core_metrics.md.
check-metric-docs: _check-nix
    @{{ dev }} cargo --quiet xtask check-metric-docs || (RC=$?; echo 'To fix automatically, run `cargo xtask check-metric-docs --fix`'; exit $RC)

# Check cargo-deny for licenses we have not already accepted.
check-licenses: _check-nix
    {{ dev }} cargo deny check licenses

# Check cargo-deny for crates on the ban list.
check-bans: _check-nix
    {{ dev }} cargo deny check bans

# Run the release-container service tests against an ephemeral postgres.
test-postgres: _check-nix
    {{ dev }} ./scripts/with-postgres.sh cargo make test-release-container-services
