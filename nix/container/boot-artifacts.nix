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
# No apt repo and no forge-scout deb. Those exist to install the agent into the
# mkosi scout initramfs; a machine booting from this payload gets the NixOS
# scout, where the agent is a package in the closure and updates arrive through
# the binary cache below. nix/deb/debs.nix still builds the deb for the mkosi
# path until that is retired — it is just not published here.
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
  # The evaluated scout system. Published as a binary cache beside the
  # squashfs so a running scout can fetch a new closure incrementally rather
  # than refetching the whole image. Optional: without it the payload still
  # serves cold boots and check-scout-updates falls back to rebooting.
  scoutSystem ? null,
}:

let
  inherit (pkgs) lib;

  # A flat-file binary cache — the same shape `nix copy --to file://` produces,
  # and usable as a substituter with the file:// or http:// prefix.
  #
  # `nix copy` cannot be used here: it is a store-to-store operation and needs
  # a store database to decide which paths are valid, which a build sandbox
  # does not have. mkBinaryCache gets the closure through
  # exportReferencesGraph, which Nix supplies to the builder directly, so it
  # works where nix copy does not.
  #
  # zstd is the default and matters: the uncompressed cache is about the size
  # of the squashfs again, and this webroot already carries both.
  scoutCache = pkgs.mkBinaryCache {
    name = "scout-cache-${arch}";
    rootPaths = [ scoutSystem ];
  };
in

pkgs.runCommand "boot-artifacts-${arch}"
  {
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

    ${lib.optionalString (scoutSystem != null) ''
      # Copied rather than symlinked, for the same reason as the squashfs: this
      # tree is served over HTTP and every hop has to dereference correctly.
      cp -r --no-preserve=mode ${scoutCache} $out/${arch}/cache
    ''}

  ''
