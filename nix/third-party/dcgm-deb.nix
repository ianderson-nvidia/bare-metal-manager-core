# NVIDIA Data Center GPU Manager, from NVIDIA's published Debian packages.
#
# scout runs DCGM diagnostics on GPU nodes, so the plugin set has to match the
# CUDA version those diagnostics were qualified against — cuda13. nixpkgs
# builds DCGM from source and pins 4.3.1, whose CMake only knows about CUDA 12;
# CUDA 13 support arrived in 4.4.1. Building it ourselves means carrying a
# rebased fix-paths patch and redoing that work on every DCGM release until
# nixpkgs bumps. Taking NVIDIA's binaries instead gives the exact artifacts
# carbide has qualified and leaves the maintenance at "bump a hash".
#
# The three packages mirror what pxe/mkosi.profiles/scout-oss-x86_64 installs:
#
#   core                 the daemon (nv-hostengine) and dcgmi
#   cuda13               diagnostic plugins built against CUDA 13
#   proprietary-cuda13   closed-source plugins the open set does not cover
#
# Their versions must match exactly — the -cuda13 package declares
# `Depends: datacenter-gpu-manager-4-core (= <same version>)`, and mixing
# versions across the plugin boundary is not something DCGM checks at runtime.
#
# Hashes come straight from the repository index rather than from a build
# failure. The index publishes them as hex, so convert rather than transcribe:
#
#   curl -sSL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/Packages.gz \
#     | gunzip | grep -A12 '^Package: datacenter-gpu-manager-4-cuda13$'
#   nix hash convert --hash-algo sha256 --to sri <hex>
{
  pkgs,
  # 4.4.2 is the newest -cuda13 build published for ubuntu2404. Note that
  # -core is published beyond this (4.6.1 at time of writing) but must be held
  # to the plugin version, per the Depends above.
  version ? "4.4.2-1",
}:

let
  baseUrl = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64";

  fetchDeb =
    name: hash:
    pkgs.fetchurl {
      url = "${baseUrl}/${name}_${version}_amd64.deb";
      inherit hash;
    };

  debs = {
    core = fetchDeb "datacenter-gpu-manager-4-core" "sha256-tqaX1pmYWN4NOtshpq7aKcnMXAzU+xSPF17hmI6URKk=";
    cuda13 = fetchDeb "datacenter-gpu-manager-4-cuda13" "sha256-+VGF2uGbPoQMfAGDcQVvbMDV5qbtkPZKtt/WN7v4OM8=";
    proprietary = fetchDeb "datacenter-gpu-manager-4-proprietary-cuda13" "sha256-TP1gyNwtDXhUqa4EvJ0qsu/tTphzvpWkl934fTBTpI4=";
  };
in

pkgs.stdenv.mkDerivation {
  pname = "dcgm";
  version = pkgs.lib.removeSuffix "-1" version;

  # Three sources, so unpackPhase is written by hand.
  srcs = builtins.attrValues debs;
  dontUnpack = true;

  nativeBuildInputs = with pkgs; [
    dpkg
    patchelf
    file
    autoPatchelfHook
  ];

  # autoPatchelfHook resolves DT_NEEDED against these. The Depends field only
  # names libc6 and lshw, but the binaries pull in rather more than dpkg
  # tracks — jsoncpp and libevent are DCGM's own dependencies, and the plugins
  # want libnuma (Recommends, not Depends, so easy to miss).
  buildInputs = with pkgs; [
    stdenv.cc.cc.lib # libstdc++
    jsoncpp
    libevent
    numactl
  ];

  # libcuda.so.1 and libnvidia-ml.so.1 come from the driver at runtime, not
  # from a package here. On NixOS they live in /run/opengl-driver/lib, which
  # is why that path leads the plugins' runpath.
  autoPatchelfIgnoreMissingDeps = [
    "libcuda.so.1"
    "libnvidia-ml.so.1"
  ];

  installPhase = ''
    runHook preInstall

    for deb in ${builtins.concatStringsSep " " (builtins.attrValues debs)}; do
      dpkg-deb -x "$deb" unpacked
    done

    mkdir -p $out
    cp -r unpacked/usr/. $out/

    # The packages install under /usr/libexec and expect to find each other by
    # relative path from the nv-hostengine binary, so the layout is preserved
    # rather than flattened into bin/ and lib/.
    runHook postInstall
  '';

  # A missing plugin does not fail a diagnostic — DCGM reports the test as
  # skipped, which reads as a pass in aggregate. The mkosi postinst checked for
  # these by path for that reason; the same check belongs here, where it fails
  # the build instead of silently under-reporting a GPU node.
  postInstall = ''
    for f in \
      $out/bin/dcgmi \
      $out/bin/nv-hostengine \
      $out/libexec/datacenter-gpu-manager-4/nvvs \
      $out/libexec/datacenter-gpu-manager-4/plugins/cuda13/BwChecker_13
    do
      if [ ! -e "$f" ]; then
        echo "ERROR: expected $f in the DCGM packages — layout has changed."
        exit 1
      fi
    done
  '';

  meta = with pkgs.lib; {
    description = "NVIDIA Data Center GPU Manager (CUDA 13 plugins), from NVIDIA's Debian packages";
    homepage = "https://developer.nvidia.com/dcgm";
    license = licenses.unfree;
    platforms = [ "x86_64-linux" ];
  };
}
