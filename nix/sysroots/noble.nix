#
# Ubuntu Noble (24.04) cc sysroots — glibc 2.39.
#
# Carbide's production binaries (Rust and any CGO-using Go) ultimately run on
# Ubuntu Noble: the DPU's rootfs is Noble, and the x86 host servers are Noble.
# nixpkgs nixos-25.11 ships glibc 2.42, so binaries linked against that nixpkgs
# would reference GLIBC_2.40+ symbols Noble's 2.39 doesn't provide — they'd fail
# at startup with `version 'GLIBC_2.40' not found`.
#
# Rather than downgrade the entire nixpkgs to a 2.39-era branch (which would
# also drag openssl, tpm2-tss, etc. back to 2024-era versions), keep current
# nixpkgs for toolchains + build-time libs and inject Noble's actual rootfs as
# a `--sysroot=...` at link time. Two sysroots — one per target arch —
# extracted from the digest-pinned `buildpack-deps:noble` image. The image
# carries libc6-dev + the full multiarch headers needed to recompile C
# dependencies (aws-lc-sys, etc.) against the sysroot.
#
# Image digests are content-addressed; pin them and Docker Hub serves the same
# bytes forever. To bump (security update etc.):
#
#   skopeo --insecure-policy inspect --raw docker://buildpack-deps:noble | \
#     jq -r '.manifests[] |
#            select(.platform.os=="linux") |
#            "\(.platform.architecture) \(.digest)"'
#
# then update the per-arch pins below and `nix build .#noble-sysroot-*` to TOFU
# the new sha256 (replace with `pkgs.lib.fakeHash` first).
#
# Usage from flake.nix:
#
#   sysroots = import ./nix/sysroots/noble.nix { inherit pkgs; };
#   noble-sysroot-x86_64 = sysroots.x86_64;
#   noble-sysroot-aarch64 = sysroots.aarch64;
#
# To instantiate against a different image tag, call `sysroots.mkSysroot`
# directly with `{ arch, imageDigest, imageSha256 }`.
#
{ pkgs }:

let
  mkSysroot =
    {
      arch,
      imageDigest,
      imageSha256,
    }:
    let
      image = pkgs.dockerTools.pullImage {
        imageName = "buildpack-deps";
        finalImageName = "buildpack-deps";
        finalImageTag = "noble";
        os = "linux";
        inherit arch imageDigest;
        sha256 = imageSha256;
      };
    in
    pkgs.runCommand "noble-sysroot-${arch}" { nativeBuildInputs = [ pkgs.jq ]; } ''
      mkdir -p extract "$out"
      tar xf ${image} -C extract
      # Reconstruct the rootfs by applying the image layers in manifest
      # order. Skip pseudo-filesystems we can't create in the sandbox.
      for layer in $(jq -r '.[0].Layers[]' extract/manifest.json); do
        # --anchored so the pseudo-fs excludes match only the top-level
        # dev/proc/sys (device nodes), NOT libc's `sys/` header dir
        # under usr/include.
        tar xf "extract/$layer" -C "$out" \
          --no-same-owner --anchored --exclude=dev --exclude=proc --exclude=sys
      done
      # Trim to a cc sysroot: headers, libraries, crt objects, the
      # dynamic linker. Drop the rest of the buildpack image
      # (compilers, docs, the package manager).
      find "$out" -mindepth 1 -maxdepth 1 \
        ! -name usr ! -name lib ! -name lib64 -exec rm -rf {} +
      find "$out/usr" -mindepth 1 -maxdepth 1 \
        ! -name include ! -name lib ! -name lib64 -exec rm -rf {} +

      # Synthesise `/include -> usr/include`. clang's GCC install
      # detection points at $sysroot/lib/gcc/<triple>/<v>/, and its
      # libstdc++ header lookup resolves a path of the form
      #   lib/gcc/<triple>/<v>/../../../../include/c++/<v>
      # which lands on $sysroot/include/c++/<v>. On a real Ubuntu host
      # with merged-usr that's already the symlink; Noble's docker
      # rootfs only merges /lib + /bin + /sbin, NOT /include — so
      # without this symlink, C++ compiles fail with "cstddef not
      # found" despite the headers being present under
      # usr/include/c++/<v>.
      ln -s usr/include "$out/include"
    '';
in
{
  inherit mkSysroot;

  x86_64 = mkSysroot {
    arch = "amd64";
    imageDigest = "sha256:6ddc88f2b2d1972421e7ed175f105b4d18785751fd896edd7f435922852e9673";
    imageSha256 = "sha256-oiBXii7BCT2j9tp6lVdQdB22n8BdznPrY81b6kl6MTU=";
  };

  aarch64 = mkSysroot {
    arch = "arm64";
    imageDigest = "sha256:8848aa4e8b721e5d259294c4a7f487710d78cd4b2aee3c29fc6b919d31f18b04";
    imageSha256 = "sha256-DLN3GVBWYu7Oblv7qXf1+ChabnjUbywO2l4DGWW3enU=";
  };
}
