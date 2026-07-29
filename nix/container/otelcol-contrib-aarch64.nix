# Custom OpenTelemetry Collector for aarch64 DPUs.
#
# Uses OCB (opentelemetry-collector-builder) to assemble a collector binary
# with three custom components from this repo:
#
#   fileresourceprocessor   — bluefield/otel/fileresourceprocessor/
#   telemetrystatsprocessor — bluefield/otel/telemetrystatsprocessor/
#   puntstatsreceiver       — bluefield/otel/puntstatsreceiver/
#
# Build phases:
#   1. ocbSource — pure sandboxed derivation. Runs OCB with
#      --skip-get-modules --skip-compilation to generate main.go and
#      components.go. Then replaces the incomplete OCB-generated go.mod/go.sum
#      with committed versions from bluefield/otel/ocb-generated/ that have the
#      full indirect dependency graph (produced by running `ocb --skip-compilation`
#      once locally — see SESSION.md).
#
#   2. crossPkgs.buildGoModule — deterministic vendor step (vendorHash below)
#      then cross-compile to aarch64. journaldreceiver requires CGO; crossPkgs
#      provides the aarch64 C toolchain and systemd.dev headers.
#
# One-time setup: run OCB locally and commit go.mod/go.sum — see SESSION.md.
#
# vendorHash update (TOFU workflow — only needed after dependency changes):
#   1. Set vendorHash = pkgs.lib.fakeHash.
#   2. Run `nix build .#otelcol-contrib-container-arm64` — fails with correct sha256.
#   3. Paste the "got:" value as vendorHash and rebuild.
{ pkgs, crossPkgs }:

let
  otelcolVersion        = "0.155.0";
  fileresourceVersion   = "0.0.1";
  telemetrystatsVersion = "0.0.1";
  puntstatsVersion      = "0.0.1";

  # Source paths resolved relative to this file (nix/container/ → root/).
  otelDir                 = ../../bluefield/otel;
  fileresourceprocessor   = ../../bluefield/otel/fileresourceprocessor;
  telemetrystatsprocessor = ../../bluefield/otel/telemetrystatsprocessor;
  puntstatsreceiver       = ../../bluefield/otel/puntstatsreceiver;

  # Committed go.mod/go.sum produced by running OCB locally (see SESSION.md).
  # If these files don't exist, the buildGoModule vendor step will fail with
  # "updates to go.mod needed" — follow SESSION.md to generate them.
  ocbGeneratedDir = ../../bluefield/otel/ocb-generated;
  hasOcbGenerated = builtins.pathExists (ocbGeneratedDir + "/go.mod");

  ocbConfig = pkgs.writeText "ocb-config.yaml" ''
    dist:
      name: otelcol-contrib
      module: otelcol-contrib
      description: Custom OpenTelemetry Collector build for DPU logging
      output_path: ./ocb-build
      otelcol_version: ${otelcolVersion}

    exporters:
      - gomod: go.opentelemetry.io/collector/exporter/debugexporter v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter v${otelcolVersion}
      - gomod: go.opentelemetry.io/collector/exporter/otlpexporter v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter v${otelcolVersion}

    extensions:
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage v${otelcolVersion}

    processors:
      - gomod: go.opentelemetry.io/collector/processor/batchprocessor v${otelcolVersion}
      - gomod: fileresourceprocessor v${fileresourceVersion}
      - gomod: go.opentelemetry.io/collector/processor/memorylimiterprocessor v${otelcolVersion}
      - gomod: telemetrystatsprocessor v${telemetrystatsVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v${otelcolVersion}

    receivers:
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/journaldreceiver v${otelcolVersion}
      - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v${otelcolVersion}
      - gomod: puntstatsreceiver v${puntstatsVersion}

    replaces:
      - fileresourceprocessor => ../fileresourceprocessor
      - telemetrystatsprocessor => ../telemetrystatsprocessor
      - puntstatsreceiver => ../puntstatsreceiver
  '';

  # Phase 1: pure sandboxed derivation — no network.
  # Generates Go source via OCB, then substitutes the committed go.mod/go.sum
  # so buildGoModule can vendor deterministically.
  ocbSource = pkgs.runCommand "otelcol-contrib-source-${otelcolVersion}" {
    nativeBuildInputs = [ pkgs.opentelemetry-collector-builder ];
  } ''
    mkdir -p $out

    # Custom modules must be siblings of ocb-build/ to match replace directives.
    cp -r ${fileresourceprocessor}   $out/fileresourceprocessor
    cp -r ${telemetrystatsprocessor} $out/telemetrystatsprocessor
    cp -r ${puntstatsreceiver}       $out/puntstatsreceiver

    cd $out
    ocb \
      --config ${ocbConfig} \
      --skip-compilation \
      --skip-get-modules

    # Replace OCB's incomplete go.mod/go.sum (no indirect deps) with the
    # committed versions that have the full module graph resolved.
    ${pkgs.lib.optionalString hasOcbGenerated ''
      cp -f ${ocbGeneratedDir}/go.mod ocb-build/go.mod
      cp -f ${ocbGeneratedDir}/go.sum  ocb-build/go.sum
    ''}
  '';

  # Wrapper scripts and runtime directories for the container.
  wrapperScripts = pkgs.runCommand "otelcol-contrib-wrapper-scripts" { } ''
    mkdir -p \
      $out/etc/otelcol-contrib/config-fragments \
      $out/var/lib/otelcol-contrib/cursors \
      $out/run/otelcol-contrib

    install -m755 ${otelDir}/otelcol-wrapper             $out/etc/otelcol-contrib/otelcol-wrapper
    install -m755 ${otelDir}/otelcol-wrapper-imports-dpf $out/etc/otelcol-contrib/otelcol-wrapper-imports
    install -m755 ${otelDir}/otelcol-wrapper-validate    $out/etc/otelcol-contrib/otelcol-wrapper-validate
  '';

in
# Phase 2: vendor modules + cross-compile to aarch64.
(crossPkgs.buildGoModule {
  pname = "otelcol-contrib";
  version = otelcolVersion;

  src = ocbSource;
  modRoot = "ocb-build";

  vendorHash = "sha256-m1YQJpy4Q67A6nXIYermk9TG7BnA3OmhLVJ56RRNUvI=";

  # journaldreceiver links against libsystemd via CGO.
  buildInputs = [ crossPkgs.systemd.dev ];

  # Place binary where the wrapper scripts expect it.
  # The binary name matches dist.name in the OCB config ("otelcol-contrib"),
  # which becomes the Go module name and therefore the installed binary name.
  postInstall = ''
    mkdir -p $out/usr/bin
    if [ -f "$out/bin/otelcol-contrib" ]; then
      mv "$out/bin/otelcol-contrib" "$out/usr/bin/otelcol-contrib"
    else
      echo "ERROR: expected $out/bin/otelcol-contrib — found:"
      ls "$out/bin/" || true
      exit 1
    fi
    rmdir --ignore-fail-on-non-empty $out/bin
  '';
}).overrideAttrs (old: {
  passthru = (old.passthru or { }) // { inherit wrapperScripts; };
})
