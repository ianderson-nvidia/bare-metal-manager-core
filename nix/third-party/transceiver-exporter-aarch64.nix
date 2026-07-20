# Pre-built wobcom transceiver-exporter for aarch64 DPUs.
#
# Prometheus exporter for optical transceiver (SFP/QSFP) metrics, scraped by
# the prometheus/transceiver receiver in the nico-otelcol collector.
#
# Keep `version` in sync with bluefield/transceiver_exporter/version.txt.
# URL template from bluefield/transceiver_exporter/url.txt.
#
# Hash update (TOFU workflow):
#   1. Set hash to pkgs.lib.fakeHash (already so below).
#   2. Run `nix build .#transceiver-exporter-container-arm64` — the fetch
#      fails with a "hash mismatch" error showing the correct sha256.
#   3. Paste the "got:" value here and rebuild.
{ pkgs, crossPkgs }:

let
  version = "1.5.0";
in
pkgs.stdenv.mkDerivation {
  pname = "transceiver-exporter-aarch64";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://github.com/wobcom/transceiver-exporter/releases/download/v${version}/transceiver-exporter-v${version}-linux-arm64.tar.gz";
    hash = pkgs.lib.fakeHash;
  };

  nativeBuildInputs = [ pkgs.patchelf ];

  unpackPhase = ''
    mkdir extract
    tar xzf $src -C extract
  '';

  installPhase = ''
    mkdir -p $out/usr/bin $out/usr/share/licenses/transceiver-exporter

    install -m755 extract/transceiver-exporter $out/usr/bin/transceiver-exporter
    install -m644 extract/LICENSE.md $out/usr/share/licenses/transceiver-exporter/LICENSE.md

    # Patch ELF interpreter and RPATH in case the binary uses CGO (links glibc).
    # This is a no-op for fully-static Go binaries (patchelf exits cleanly).
    interp="${crossPkgs.stdenv.cc.libc}/lib/ld-linux-aarch64.so.1"
    rpath="${crossPkgs.stdenv.cc.libc}/lib:${crossPkgs.stdenv.cc.cc.lib}/lib"
    patchelf --set-interpreter "$interp" --set-rpath "$rpath" \
      $out/usr/bin/transceiver-exporter || true
  '';
}
