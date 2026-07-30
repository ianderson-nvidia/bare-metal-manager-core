# Mellanox Firmware Tools (MFT) for x86_64 hosts.
#
# The scout discovery image ships the full MFT suite — 57 binaries including
# flint, mst, mlxconfig, mlxlink, mlxfwreset and mlxcables. nixpkgs' `mstflint`
# is the open-source subset and provides only a handful of those, so a scout
# built on mstflint alone loses NIC firmware management and link diagnostics
# with nothing more informative than "command not found".
#
# MFT arrives in the mkosi profile as a bare `mft` at the end of the NV_PACKAGES
# list in mkosi.postinst.chroot, which is easy to miss when reading the package
# list in mkosi.conf.
#
# This is the x86_64 counterpart of mft-aarch64.nix; the tarball layout and the
# patchelf handling are the same, only the interpreter and target differ.
{ pkgs }:

let
  version = "4.35.0-159";
  interp = "${pkgs.stdenv.cc.libc}/lib/ld-linux-x86-64.so.2";
  # The MFT binaries link against glibc and libstdc++ only.
  rpath = "${pkgs.stdenv.cc.libc}/lib:${pkgs.stdenv.cc.cc.lib}/lib";
in
pkgs.stdenv.mkDerivation {
  pname = "mft-x86_64";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://www.mellanox.com/downloads/MFT/mft-${version}-x86_64-deb.tgz";
    hash = "sha256-anwF1gyMSBkRCjVvcsvGaevhjfiiqCefDe2IrEKdrvk=";
  };

  nativeBuildInputs = [
    pkgs.dpkg
    pkgs.patchelf
    pkgs.file
  ];

  unpackPhase = ''
    tar xzf $src
    dpkg-deb -x mft-${version}-x86_64-deb/DEBS/mft_${version}_amd64.deb extracted
  '';

  installPhase = ''
    # Several MFT entry points are shell or Python wrappers that locate their
    # real ELF alongside themselves — flint calls flint_ext, mlxfwreset calls
    # into usr/lib64/mft. Copy the whole tree rather than cherry-picking, or
    # the wrappers resolve to nothing.
    mkdir -p $out/usr/bin $out/usr/lib64/mft
    cp -r extracted/usr/bin/. $out/usr/bin/
    cp -r extracted/usr/lib64/mft/. $out/usr/lib64/mft/

    # Tools that hardcode /opt/mellanox/mft/bin find their companions here.
    mkdir -p $out/opt/mellanox/mft
    ln -sf /usr/bin $out/opt/mellanox/mft/bin

    # Patch ELF executables: interpreter + RPATH. Shared objects get RPATH
    # only — setting an interpreter on a .so is meaningless and patchelf will
    # refuse. Non-ELF files (the wrapper scripts, Python, static archives) are
    # skipped by the file(1) check; a patchelf failure on something that *is*
    # ELF is a real error and should not be swallowed.
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

    # The suite is meant to arrive whole. Spot-check the tools carbide reaches
    # for, so a tarball that reorganises fails here rather than at discovery.
    for bin in flint flint_ext mst mlxconfig mlxlink mlxfwreset; do
      if [ ! -e "$out/usr/bin/$bin" ]; then
        echo "ERROR: $bin missing from the MFT tarball — layout has changed."
        exit 1
      fi
    done
  '';

  meta = {
    description = "Mellanox Firmware Tools for x86_64";
    homepage = "https://network.nvidia.com/products/adapter-software/firmware-tools/";
    license = pkgs.lib.licenses.unfree;
    platforms = [ "x86_64-linux" ];
  };
}
