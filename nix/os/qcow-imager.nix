# The qcow imager, as a NixOS system.
#
# Counterpart of the qcow-imager mkosi profiles. iPXE chains this UKI directly —
# there is no loader stage and no second fetch, because unlike scout the image
# is small and the work is short: write a customer's qcow2 onto local disk,
# resize the root filesystem, fix up the bootloader, and get out of the way.
#
# crates/ipxe-renderer/templates.yaml drives it:
#
#   chain ${base_url}/internal/${arch}/qcow-imager.efi loglevel=7 console=tty0 \
#     pci=realloc=off console=${console} image_url={{image_url}} {{extra}}
#
# so the filename is fixed and every parameter arrives on the kernel command
# line. pxe/common_files/disk_imaging.sh parses them itself — image_url,
# image_sha, image_disk, image_distro_*, rootfs_uuid, bootfs_uuid, efifs_uuid,
# rootfs_label, update_grub_template, update_grub_cfg, create_forge_test_user
# and a cloud-init ds= — so none of that surfaces here. This module's whole job
# is to boot, provide the tools the script shells out to, and run it.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:

let
  # The imaging script, unchanged from the tree that the mkosi profiles copied
  # into /opt/forge. It is 579 lines of bash that ends by chrooting into the
  # filesystem it just wrote, so it stays a file rather than being inlined.
  #
  # writeShellScriptBin, deliberately not writeShellApplication: the latter
  # injects `set -euo pipefail`, and this script runs without `set -e` on
  # purpose. Nearly every step is piped through `tee` to the operator console,
  # so `$?` is the tee's rather than the command's, and several probes — the
  # serial port detection especially — are expected to fail before finding one
  # that works. Adding -e turns a working imager into one that aborts on the
  # first absent /dev/ttyS1.
  diskImaging = pkgs.writeShellScriptBin "disk_imaging.sh" (
    builtins.readFile ../../pxe/common_files/disk_imaging.sh
  );

  # Everything disk_imaging.sh shells out to, verified against the script
  # rather than copied from the mkosi package list: awk blkid chroot curl grep
  # growpart lvm mount nvme partprobe qemu-img resize2fs sed sgdisk udevadm
  # umount update-grub.
  #
  # update-grub is deliberately absent. The script runs it as
  # `chroot /mnt /bin/sh -c update-grub`, so it has to resolve inside the
  # *imaged* filesystem — the customer's grub, configured for the customer's
  # disk. Providing one here would be the wrong grub even if it worked.
  imagingPath = with pkgs; [
    qemu-utils # qemu-img convert
    cloud-utils # growpart
    e2fsprogs # resize2fs
    gptfdisk # sgdisk
    parted # partprobe
    lvm2
    nvme-cli
    util-linux # blkid, mount, umount, lsblk
    curl
    coreutils
    gawk
    gnused
    gnugrep
    findutils
    systemd # udevadm
    bashInteractive
  ];
in

{
  # netboot.nix, as with the other two images — the mechanism for packing a
  # whole system into one artifact, without the installer profiles.
  imports = [
    (modulesPath + "/installer/netboot/netboot.nix")
    ./common/console.nix
    ./common/modprobe-hardening.nix
  ];

  # mkosi installed linux-image-virtual, which was wrong for the job: this
  # image has to find NVMe and SAS controllers on machines nobody enumerated in
  # advance, and find_bootdisk() probes /dev/nvme0n1 and then /dev/sda. A
  # virtual-only kernel finds neither on real hardware.
  hardware.enableAllHardware = true;
  # As in scout: linux-firmware is 770 MB and this image does not need a NIC
  # that requires a blob in order to write a disk. Forced because
  # enableAllHardware turns it on.
  hardware.enableRedistributableFirmware = lib.mkForce false;
  boot.initrd.includeDefaultModules = true;

  # ==========================================================================
  # Keep it small
  #
  # iPXE transfers this whole image before the machine can do anything, so the
  # same trimming as the other two applies.
  # ==========================================================================
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
  fonts.fontconfig.enable = false;
  i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
  hardware.graphics.enable = false;
  services.speechd.enable = false;
  # Nothing here evaluates a derivation, substitutes a path or rebuilds itself.
  # scout sets this true because it updates itself from a binary cache; this
  # image runs once and is discarded.
  nix.enable = false;
  # The imager writes a qcow2 onto a raw disk. It never creates a pool, and zfs
  # is a large chunk of closure for a filesystem it will not encounter.
  boot.supportedFilesystems.zfs = lib.mkForce false;
  environment.defaultPackages = lib.mkForce [ ];

  networking.hostName = "qcow-imager";

  # Console, networkd and the DHCP match come from nix/os/common/console.nix.
  # That file is also where console=ttyAMA0 is added on aarch64, which matters
  # more here than anywhere else: get_serial_port() probes ttyS0, ttyS1 and
  # ttyAMA0 and writes progress to the first that works, so on a Grace machine
  # where the kernel never brought ttyAMA0 up the operator watches a blank
  # console while the disk is rewritten.

  # mkosi installed systemd-resolved and systemd-timesyncd as packages; these
  # are the options that turn them on.
  services.resolved.enable = true;
  services.timesyncd.enable = true;

  # openssh-server was in the mkosi package list, and imaging is exactly the
  # operation someone wants to watch when it goes wrong. The image is ephemeral
  # and reachable only from the provisioning network.
  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "yes";
  };
  # mkosi set RootPassword=password for console debugging. netboot.nix already
  # leaves root passwordless, which serves the same purpose without a shared
  # secret in the tree.

  # The mkosi package list, mapped. Dropped as Debian-only or meaningless here:
  # debconf-utils, keyboard-configuration, libargtable2-0, libudev-dev,
  # linux-image-virtual, systemd-boot (this is a UKI — there is no bootloader
  # inside the image), and systemd-{resolved,timesyncd}, which are options
  # above rather than packages. vim-nox is dropped in favour of the smaller
  # editor below; nothing scripts against it.
  environment.systemPackages =
    imagingPath
    ++ (with pkgs; [
      diskImaging
      dmidecode
      efibootmgr
      file
      iproute2
      iputils
      lshw
      mstflint
      nettools
      pciutils
      smartmontools
      tpm2-tools
      tpm2-tss
      vim
      wget
    ]);

  # etc/systemd/system/disk-imaging.service, preserved in behaviour.
  systemd.services.disk-imaging = {
    description = "Disk imaging service";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];

    # A PATH rather than an absolute store path in ExecStart, and deliberately
    # so. The script chroots into the filesystem it has just written and runs
    # commands there; resolving everything to /nix/store up front would send
    # those at this image's binaries instead of the customer's.
    path = imagingPath;

    serviceConfig = {
      # Type=idle, not oneshot: the script writes progress directly to the
      # serial console it picked, and idle holds it back until the rest of the
      # boot has stopped writing, so the two do not interleave.
      Type = "idle";
      ExecStart = "${diskImaging}/bin/disk_imaging.sh";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  # No counterpart to qcow-imager-aarch64/mkosi.postinst.chroot, which gunzips
  # /lib/modules/*/vmlinuz. That exists because Ubuntu ships a gzipped arm64
  # kernel and the UKI stub needs it raw. NixOS builds an uncompressed Image on
  # aarch64 — stdenv.hostPlatform.linux-kernel.target — which nix/os/uki.nix
  # picks up directly, so there is nothing to decompress.

  system.stateVersion = lib.mkDefault "25.11";
}
