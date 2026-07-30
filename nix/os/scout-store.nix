# The scout root filesystem, as the squashfs the loader fetches at boot.
#
# This is the Nix counterpart of the scout-oss mkosi profile's scout.squashfs.
# The loader (pxe/mkosi.profiles/scout-loader-*/mkosi.extra/etc/rc.local) pulls
# it over HTTP, measures it into TPM PCR 16, loop-mounts it under an overlayfs
# and soft-reboots into it — so iPXE only ever transfers the small loader image
# and the large transfer happens from Linux userspace, with retries.
#
# Two files are produced, and they have to travel together:
#
#   scout-store.squashfs      the Nix store closure of the scout system
#   scout-store.nixos-system  the toplevel path held inside that squashfs
#
# NixOS differs from the Ubuntu rootfs this replaces: the squashfs holds only
# /nix/store, and the rest of the root is synthesised at boot by the toplevel's
# init. The loader therefore has to be told which toplevel to start, and that
# path changes with every scout rebuild. Writing it beside the squashfs — rather
# than passing it on the kernel command line — keeps the pair atomic: one
# artifact directory, staged in one step, impossible to half-update.
{
  pkgs,
  nixosSystem,
  name ? "scout-store",
}:

let
  inherit (nixosSystem) config;
in

pkgs.runCommand name
  {
    meta.description = "Scout root filesystem squashfs and its toplevel path";
    passthru.toplevel = config.system.build.toplevel;
  }
  ''
    mkdir -p $out

    # The netboot module already builds exactly this squashfs; reuse it rather
    # than running make-squashfs again with settings that could drift from what
    # the initrd path produces.
    #
    # Copied, not symlinked. These artifacts get staged into a webroot and
    # served over HTTP, and every step between here and there — install, rsync,
    # tar, an HTTP server resolving a path — has to dereference a symlink
    # correctly or the consumer receives 56 bytes of link text instead of a
    # gigabyte of squashfs. The duplicate in the store is worth not having that
    # failure mode, because it surfaces as a corrupt image at boot rather than
    # as an error at build time.
    cp --reflink=auto -L ${config.system.build.squashfsStore} $out/${name}.squashfs
    chmod 0444 $out/${name}.squashfs

    # Consumed by the loader to decide what to soft-reboot into. Kept as a bare
    # path with no trailing newline so a shell can read it with $(cat ...).
    printf '%s' "${config.system.build.toplevel}" > $out/${name}.nixos-system

    {
      echo "squashfs: $(du -Lh $out/${name}.squashfs | cut -f1)"
      echo "toplevel: $(cat $out/${name}.nixos-system)"
    } | tee $out/sizes.txt
  ''
