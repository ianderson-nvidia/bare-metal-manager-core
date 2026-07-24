# Pre-built Mellanox Firmware Tools (MFT) for aarch64 DPUs.
#
# Provides the full MFT suite including:
#   flint     — NIC firmware query/flash/lockdown (bash wrapper → flint_ext ELF)
#   mlxfwreset — firmware reset (shell wrapper → Python tools in usr/lib64/mft/)
#
# Used by forge-dpu-agent via crates/libmlx. The agent looks for:
#   flint        on PATH or /usr/bin/flint, /opt/mellanox/mft/bin/flint
#   mlxfwreset   at /opt/mellanox/mft/bin/mlxfwreset (hardcoded in reset.rs)
#
# mlxfwreset is a shell script that invokes Python tools; the container runtime
# must include Python 3 (added to forge-dpu-agent runtime in flake.nix).
#
# The tarball is fetched from Mellanox's public download server.
# hash is the sha256 of the tarball (already set).
{ pkgs, crossPkgs }:

let
  version = "4.35.0-159";
  interp = "${crossPkgs.stdenv.cc.libc}/lib/ld-linux-aarch64.so.1";
  # flint_ext links against standard glibc + libstdc++ only.
  rpath = "${crossPkgs.stdenv.cc.libc}/lib:${crossPkgs.stdenv.cc.cc.lib}/lib";
in
pkgs.stdenv.mkDerivation {
  pname = "mft-aarch64";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://www.mellanox.com/downloads/MFT/mft-${version}-aarch64-deb.tgz";
    hash = "sha256-7bn/4qrBSGdIFs2Tw9iyYO8rSpvg4nHavNFKAwC6diM=";
  };

  nativeBuildInputs = [ pkgs.dpkg pkgs.patchelf pkgs.file ];

  unpackPhase = ''
    tar xzf $src
    dpkg-deb -x mft-${version}-aarch64-deb/DEBS/mft_${version}_arm64.deb extracted
  '';

  installPhase = ''
    # Copy the full MFT tree so wrapper scripts find their companions.
    mkdir -p $out/usr/bin $out/usr/lib64/mft
    cp -r extracted/usr/bin/. $out/usr/bin/
    cp -r extracted/usr/lib64/mft/. $out/usr/lib64/mft/

    # The agent hardcodes /opt/mellanox/mft/bin/mlxfwreset (libmlx/firmware/reset.rs).
    # Symlink that tree to /usr/bin so the shell wrappers resolve correctly.
    mkdir -p $out/opt/mellanox/mft
    ln -sf /usr/bin $out/opt/mellanox/mft/bin

    # Patch ELF executables: set interpreter + RPATH.
    # Patch shared objects (.so): set RPATH only (no interpreter).
    # Non-ELF files (shell scripts, Python, static archives) are skipped by the
    # file(1) type check; any patchelf failure on an ELF file is a real error.
    find $out -type f | while IFS= read -r f; do
      type=$(file -b "$f") || continue
      case "$type" in
        *"ELF"*"executable"*)
          patchelf --set-interpreter "${interp}" --set-rpath "${rpath}" "$f"
          ;;
        *"ELF"*"shared object"*)
          patchelf --set-rpath "${rpath}" "$f"
          ;;
      esac
    done
  '';
}
