# The NVIDIA datacenter driver, re-declared so it builds on aarch64 too.
#
# nixpkgs' `nvidiaPackages.dc_590` is x86_64-only, and its fabricmanager is
# broken on aarch64 in two separate ways. All three problems come from the same
# root cause: nixpkgs derives NVIDIA's download paths by transforming
# `stdenv.system`, and NVIDIA does not name its aarch64 server artifacts the
# way that transformation predicts. They call it `sbsa`.
#
# What this file fixes, in order of how loudly each fails:
#
#   1. dc_590 declares no sha256_aarch64, so `meta.platforms` is x86_64 only
#      and evaluating it for aarch64 fails with "unsupported system".
#      generic.nix has had the aarch64 branch for years — the hash is the only
#      missing input, and supplying it is what adds the platform.
#
#   2. fabricmanager's source 404s. fabricmanager.nix builds its URL from
#      `sys`, which reverses stdenv.system into `linux-aarch64`; NVIDIA
#      publishes that archive under `linux-sbsa`.
#
#   3. fabricmanager's ELF interpreter does not exist. The same `sys` value
#      feeds `--set-interpreter .../ld-linux-aarch64.so.2`, but aarch64 glibc
#      ships `ld-linux-aarch64.so.1`. patchelf sets a non-existent interpreter
#      without complaining, so this one *builds clean* and fails at exec with
#      `No such file or directory`, which names the binary rather than the
#      interpreter and reads like the binary is missing.
#
# (2) currently masks (3): the fetch fails before anything can be patched. Fix
# only the URL and you get a fabricmanager that builds and cannot run. Both are
# worth reporting upstream — on x86_64 the same expressions are correct, which
# is why neither has been noticed.
#
# Scope: this is deliberately not a nixpkgs overlay. It needs the kernel
# package set's scope for `kernel` and `kernelModuleMakeFlags`, and confining
# it here avoids rebuilding every other consumer of nvidiaPackages.
{
  lib,
  pkgs,
  # The kernel package set the modules must be built against — pass
  # config.boot.kernelPackages, not a bare pkgs.
  kernelPackages,
  version ? "590.48.01",
}:

let
  inherit (pkgs.stdenv.hostPlatform) isAarch64;

  # NVIDIA's own name for 64-bit Arm servers. Both the driver's tesla path and
  # the fabricmanager redist use it; nixpkgs guesses `linux-aarch64` for the
  # latter and gets a 404.
  driverArch = if isAarch64 then "aarch64" else "x86_64";
  redistArch = if isAarch64 then "linux-sbsa" else "linux-x86_64";

  # generic.nix consumes `url` in *both* architecture branches — when the
  # argument is present it wins unconditionally — so it has to be conditional
  # here rather than a single string. The datacenter builds live under /tesla/,
  # not the /XFree86/ path generic.nix would otherwise default to.
  driverUrl = "https://us.download.nvidia.com/tesla/${version}/NVIDIA-Linux-${driverArch}-${version}.run";

  fabricmanagerUrl =
    "https://developer.download.nvidia.com/compute/nvidia-driver/redist/fabricmanager/"
    + "${redistArch}/fabricmanager-${redistArch}-${version}-archive.tar.xz";

  # Hashes come from `nix store prefetch-file` against the URLs above rather
  # than from a failed build, so a wrong one is a mismatch error rather than a
  # silently different artifact. The aarch64 driver hash independently matches
  # the `sha256_aarch64` nixpkgs already carries for `new_feature`, which is
  # this same 590.48.01 driver declared on the feature branch instead of the
  # datacenter one — a useful cross-check, but not a substitute for dc_590,
  # since that declaration has no fabricmanager.
  hashes = {
    x86_64 = {
      driver = "sha256-ueL4BpN4FDHMh/TNKRCeEz3Oy1ClDWto1LO/LWlr1ok=";
      fabricmanager = "sha256-f/AQ8HrgoqBQyXNrXA/UaI4OMQ9QcjjYWIhr1/5uM74=";
    };
    aarch64 = {
      driver = "sha256-FOz7f6pW1NGM2f74kbP6LbNijxKj5ZtZ08bm0aC+/YA=";
      fabricmanager = "sha256-sT4Mq3lW1seWeqGlmQ3bnS2591VqaUkbEiEzUzeS93U=";
    };
  };
  h = if isAarch64 then hashes.aarch64 else hashes.x86_64;

  # persistenced and the open kernel modules are built from architecture-neutral
  # source tarballs, so those hashes are shared.
  driver = kernelPackages.callPackage
    (import (pkgs.path + "/pkgs/os-specific/linux/nvidia-x11/generic.nix") {
      inherit version;
      url = driverUrl;

      sha256_64bit = hashes.x86_64.driver;
      sha256_aarch64 = hashes.aarch64.driver;

      persistencedSha256 = "sha256-wsNeuw7IaY6Qc/i/AzT/4N82lPjkwfrhxidKWUtcwW8=";
      openSha256 = "sha256-hECHfguzwduEfPo5pCDjWE/MjtRDhINVr4b1awFdP44=";
      fabricmanagerSha256 = h.fabricmanager;

      useSettings = false;
      usePersistenced = true;
      useFabricmanager = true;
    })
    { };
in

# On x86_64 this is exactly nixpkgs' dc_590: every argument above matches that
# declaration, and the override below is skipped entirely. Guarding the whole
# override rather than making its contents conditional matters — setting
# `postInstall = ""` where the attribute was previously absent is enough to
# change the derivation hash, so an "empty" override is not a no-op.
if !isAarch64 then
  driver
else
  driver.overrideAttrs (old: {
    passthru = old.passthru // {
      fabricmanager = old.passthru.fabricmanager.overrideAttrs (fmOld: {
        src = pkgs.fetchurl {
          url = fabricmanagerUrl;
          hash = h.fabricmanager;
        };

        # postInstall, not postFixup: fabricmanager.nix sets `dontFixup = true`
        # (its comment says stdenv's shrinking leaves undefined symbols in these
        # prebuilt binaries), so the whole fixup phase — and any postFixup hook
        # — never runs. Its installPhase does end in `runHook postInstall`,
        # which lands after the wrong interpreter is set and before the
        # versionCheckHook tries to execute the binary.
        postInstall = (fmOld.postInstall or "") + ''
          for b in nv-fabricmanager nvswitch-audit; do
            ${pkgs.patchelf}/bin/patchelf \
              --set-interpreter ${pkgs.stdenv.cc.libc}/lib/ld-linux-aarch64.so.1 \
              "$out/bin/$b"
          done

          # Assert rather than trust: a non-existent interpreter is exactly the
          # failure this file exists to prevent, and patchelf will not report it.
          for b in nv-fabricmanager nvswitch-audit; do
            interp=$(${pkgs.patchelf}/bin/patchelf --print-interpreter "$out/bin/$b")
            if [ ! -e "$interp" ]; then
              echo "ERROR: $b has interpreter $interp, which does not exist."
              exit 1
            fi
          done
        '';
      });
    };
  })
