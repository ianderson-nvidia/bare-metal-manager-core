# The boot-artifacts payload, assembled from Nix outputs.
#
# Replaces dev/docker/Dockerfile.release-artifacts-<arch>, which is
#
#   FROM $CONTAINER_RUNTIME
#   COPY pxe/static/blobs/internal/ /
#   CMD exec /bin/sh -c "trap : TERM INT; sleep 9999999999d & wait"
#
# — a carrier image with no program of its own. nico-pxe runs it as an init
# container that copies the tree into a shared volume before the web server
# starts:
#
#   command: ["sh", "-c", "cp -r /x86_64 /forge-boot-artifacts/blobs/internal"]
#
# so the layout below has to match what that `cp` names. The keep-alive CMD is
# supplied by the container builder, the same way machine-validation-config
# gets one; see nix/services/default.nix.
#
# What this removes is the staging round-trip. Today the artifacts are built,
# installed into pxe/static/blobs/internal by cargo-make tasks, and then a
# Dockerfile copies that directory in — so the image's contents depend on
# whatever happens to be in the working tree, including artifacts left over
# from earlier builds. Assembling from the derivations instead means the image
# holds exactly what this flake produced and nothing else.
{
  pkgs,
  # Architecture directory name inside the image: x86_64 or aarch64. This is
  # the string nico-pxe's init container copies, not a Nix system tuple.
  arch,
  # iPXE bootloaders — provides blobs/<arch>/{ipxe,golan}.efi.
  ipxe,
  # The netboot loader UKI, published as scout.efi because that is the name
  # crates/ipxe-renderer/templates.yaml tells iPXE to fetch.
  scoutLoader,
  # scout-store: the squashfs the loader fetches, and the toplevel path that
  # names the system inside it. Both or neither — see nix/os/scout-store.nix.
  scoutStore ? null,
  # forge-scout .deb, published through a minimal apt repo the scout initramfs
  # installs from. Optional: an image without it is still a valid carrier.
  scoutDeb ? null,
}:

let
  inherit (pkgs) lib;

  # Written as a file rather than a heredoc in the build script: the script is
  # an indented Nix string, and a `<<EOF` terminator has to sit at column zero,
  # so any reformatting of this file would silently produce an unterminated
  # heredoc.
  aptRelease = pkgs.writeText "Release" ''
    Origin: Ubuntu
    Label: Ubuntu
    Suite: focal
    Codename: focal
    Architectures: amd64
    Components: main
  '';
in

pkgs.runCommand "boot-artifacts-${arch}"
  {
    nativeBuildInputs = lib.optionals (scoutDeb != null) [ pkgs.dpkg ];
    meta.description = "Boot artifacts payload for ${arch}";
  }
  ''
    mkdir -p $out/${arch}

    # install rather than cp: store files are 0444, and the init container's
    # `cp -r` would carry that through to the served webroot.
    install -m 0644 ${ipxe}/blobs/${arch}/ipxe.efi  $out/${arch}/ipxe.efi
    install -m 0644 ${ipxe}/blobs/${arch}/golan.efi $out/${arch}/golan.efi

    install -m 0644 ${scoutLoader}/scout-loader.efi $out/${arch}/scout.efi

    ${lib.optionalString (scoutStore != null) ''
      install -m 0644 ${scoutStore}/scout-store.squashfs     $out/${arch}/scout.squashfs
      install -m 0644 ${scoutStore}/scout-store.nixos-system $out/${arch}/scout.nixos-system
    ''}

    ${lib.optionalString (scoutDeb != null) ''
      # The scout initramfs installs forge-scout with apt, so the deb has to be
      # reachable through a repository rather than as a loose file. This is the
      # smallest thing dpkg-scanpackages will accept: one pool, one suite, no
      # signing — the repo is served over the provisioning network only, and
      # the initramfs trusts it explicitly.
      poolDir=$out/apt/pool/base/f/forge-scout
      distDir=$out/apt/dists/focal/main/binary-amd64
      mkdir -p "$poolDir" "$distDir"

      install -m 0644 ${scoutDeb}/*.deb "$poolDir/"

      cd $out/apt
      dpkg-scanpackages --arch amd64 -m pool > "$distDir/Packages"
      install -m 0644 ${aptRelease} dists/focal/Release
    ''}
  ''
