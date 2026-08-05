# The scout root filesystem, as the kernel and initrd the loader kexecs into.
#
# Replaces the scout-oss mkosi profile's scout.squashfs. The loader pulls these
# over HTTP, measures the initrd into TPM PCR 16 and kexecs — so iPXE only ever
# transfers the small loader image, and the large transfer happens from Linux
# userspace with retries and a URL chosen at runtime.
#
# Three files are produced and they have to travel together:
#
#   scout.kernel    the kernel scout boots
#   scout.initrd    that kernel's initrd, with the whole Nix store inside it
#   scout.cmdline   the command line, including which system to activate
#
# Why not a bare squashfs, as mkosi shipped:
#
# mkosi's image was an Ubuntu root filesystem — a complete tree with a
# populated /etc — so the loader could mount it and soft-reboot into it. A
# NixOS system does not have that shape. `system.build.squashfsStore` holds
# only /nix/store; /etc and every systemd unit are produced by the toplevel's
# activation, which runs from stage 1. Handing systemd a store-only root
# leaves it with no units at all ("Unit default.target not found"), and there
# is no way to fix that from the loader side without running NixOS activation
# against a chroot. Booting the system's own kernel through the ordinary NixOS
# path avoids the whole problem.
#
# It also removes a coupling that was invisible: a soft-reboot never restarts
# the kernel, so scout would have run on the *loader's* kernel and never its
# own. Those happen to be the same derivation today, but scout's NVIDIA modules
# are built against a specific kernel version, and the aarch64 profile wants a
# 64K-page Grace kernel the loader has no reason to carry. Under kexec the
# kernel and its modules always match, because they ship together.
{
  nixosSystem,
  name ? "scout",
}:

let
  inherit (nixosSystem) config pkgs;

  # netbootRamdisk is the initrd with the store squashfs prepended, so the
  # machine needs nothing beyond these two files and the command line.
  kernel = "${config.system.build.kernel}/${pkgs.stdenv.hostPlatform.linux-kernel.target}";
  initrd = "${config.system.build.netbootRamdisk}/initrd";

  # The same command line system.build.kexecScript bakes. `init=` is the part
  # the loader cannot invent: it names the toplevel to activate, and it changes
  # with every scout rebuild. The rest are the system's own kernelParams —
  # console settings and the netboot module's root=fstab — which the loader has
  # no way to know either.
  #
  # Published as a file rather than passed on the loader's own command line so
  # that the three artifacts stay self-describing: whatever is in the webroot
  # boots, with no build-time knowledge held anywhere else.
  cmdline = pkgs.lib.concatStringsSep " " (
    [ "init=${config.system.build.toplevel}/init" ] ++ config.boot.kernelParams
  );
in

pkgs.runCommand name
  {
    meta.description = "Scout kernel, initrd and command line for kexec";
    passthru.toplevel = config.system.build.toplevel;
  }
  ''
    mkdir -p $out

    # Copied, not symlinked. These artifacts get staged into a webroot and
    # served over HTTP, and every step between here and there — install, rsync,
    # tar, an HTTP server resolving a path — has to dereference a symlink
    # correctly or the consumer receives a few dozen bytes of link text instead
    # of a gigabyte of initrd. The duplicate in the store is worth not having
    # that failure mode, because it surfaces as a corrupt image at boot rather
    # than as an error at build time.
    cp --reflink=auto -L ${kernel} $out/${name}.kernel
    cp --reflink=auto -L ${initrd} $out/${name}.initrd
    chmod 0444 $out/${name}.kernel $out/${name}.initrd

    # No trailing newline: the loader reads this with $(cat ...) and appends
    # its own per-machine parameters after it.
    printf '%s' ${pkgs.lib.escapeShellArg cmdline} > $out/${name}.cmdline

    {
      echo "kernel:  $(du -Lh $out/${name}.kernel | cut -f1)"
      echo "initrd:  $(du -Lh $out/${name}.initrd | cut -f1)"
      echo "cmdline: $(cat $out/${name}.cmdline)"
    } | tee $out/sizes.txt
  ''
