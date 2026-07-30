# The scout loader, as a NixOS system.
#
# Counterpart of the scout-loader mkosi profile. iPXE boots this small image;
# it fetches the much larger scout root filesystem over HTTP, measures it into
# the TPM, mounts it and soft-reboots into it. Keeping the two stages separate
# is what keeps the iPXE transfer down to tens of megabytes — the ~1.5 GB fetch
# happens from Linux userspace, where it can retry, report progress and pick a
# URL at runtime.
#
# Behaviour follows pxe/common_files/scout-loader-rclocal:
#
#   newrootfs=<url>   override the image to fetch
#   newrootfs=none    stay in the loader, for debugging
#   console=...       every console on the cmdline gets progress messages
#   PCR 16            extended with the digest of what was fetched
#
# What differs is the mount layout, because a NixOS root is not shaped like the
# Ubuntu one this replaces. Its squashfs holds only the contents of /nix/store;
# /etc, /bin and the rest are produced at boot by the system's activation
# script. So the new root is a tmpfs with the store mounted underneath it,
# rather than the squashfs being the root.
#
# Which system to start cannot be read off the image — a store may hold several
# — so it is published beside the squashfs as a bare store path in
# <name>.nixos-system. See nix/os/scout-store.nix.
{
  lib,
  pkgs,
  modulesPath,
  ...
}:

let
  # Everything the loader script shells out to. Collected here so the unit runs
  # with an explicit PATH rather than inheriting whatever the system profile
  # happens to contain.
  loaderPath = with pkgs; [
    curl
    zstd
    cpio
    gnutar
    util-linux
    kmod
    coreutils
    gnused
    gnugrep
    gawk
    tpm2-tools
    systemd
  ];
in

{
  # netboot.nix directly, not netboot-minimal.nix.
  #
  # The chain is netboot-minimal -> netboot-base -> netboot.nix plus
  # profiles/base.nix and profiles/installation-device.nix. Those profiles
  # exist so a netbooted machine can install NixOS onto a disk, and they bring
  # a copy of nixpkgs (196 MB, via cd-dvd/channel.nix), python3 (127 MB), perl
  # (55 MB) and vim (43 MB) with them. "minimal" is minimal relative to a
  # graphical installer, not to a loader that fetches one file and pivots.
  #
  # netboot.nix on its own is the mechanism — squashfsStore, netbootRamdisk,
  # and the tmpfs-root / overlay-store filesystem layout — with none of the
  # installer.
  imports = [
    (modulesPath + "/installer/netboot/netboot.nix")
  ];

  # ==========================================================================
  # Keep it small
  #
  # This image is what iPXE transfers, so its size is the cost paid before a
  # machine can do anything. It holds no discovery tooling, no GPU stack and no
  # agent — only enough to fetch and pivot.
  # ==========================================================================
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
  fonts.fontconfig.enable = false;
  i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
  nix.enable = false;

  # netboot.nix's register-nix-paths unit is left enabled. It runs
  # `nix-store --load-db` to populate the store database, which is empty on the
  # tmpfs root even though the paths themselves are in the squashfs, and it
  # keeps nix in the closure — nix links boost, which links icu4c, for about
  # 40 MB. Nothing in the loader queries the store, so that is dead weight
  # here, but leaving the unit alone keeps this image behaving like any other
  # NixOS netboot system rather than one with a surprise removed from it.
  hardware.graphics.enable = false;
  services.speechd.enable = false;
  boot.supportedFilesystems.zfs = lib.mkForce false;

  networking.networkmanager.enable = lib.mkForce false;
  networking.wireless.enable = lib.mkForce false;
  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  networking.hostName = "scout-loader";

  systemd.network.networks."10-dhcp" = {
    matchConfig.Name = "enx* enp* enP*";
    networkConfig.DHCP = "yes";
    dhcpV4Config.ClientIdentifier = "mac";
  };

  boot.kernelParams = [
    "console=tty0"
    "console=ttyS0,115200"
  ];

  # Stage 1 here mounts a squashfs out of the initramfs and nothing else — no
  # disk, no network, no encryption. The default module set exists for booting
  # off unknown storage controllers, which never happens in this image.
  boot.initrd.includeDefaultModules = false;

  # Loaded once userspace is running: loop and squashfs to mount the fetched
  # image, overlay to put a writable layer over it. The NIC driver is bound by
  # udev from the full module tree, which ships with the kernel regardless.
  boot.kernelModules = [
    "loop"
    "squashfs"
    "overlay"
  ];

  # profiles/base.nix supplied these; without it the defaults are whatever
  # nixpkgs ships, which includes an editor and assorted shell tooling this
  # image never uses. Everything the loader runs is named in its unit's path.
  environment.defaultPackages = lib.mkForce [ ];

  # installation-device.nix left root passwordless so a failed boot could be
  # debugged on the console. Worth keeping for newrootfs=none, and the image is
  # ephemeral and reachable only from the provisioning network.
  users.users.root.initialHashedPassword = "";

  # ==========================================================================
  # The loader
  # ==========================================================================
  systemd.services.scout-loader = {
    description = "Fetch the scout root filesystem and soft-reboot into it";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    path = loaderPath;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StandardOutput = "journal+console";
    };
    script = ''
      set -u

      PCR=16
      IMAGE=/run/scout-rootfs.squashfs
      NEXTROOT=/run/nextroot

      cmdline_value() {
        sed 's/ /\n/g' /proc/cmdline | grep "^$1=" | cut -d= -f2- | tail -1
      }

      url=$(cmdline_value newrootfs)
      if [ -z "$url" ]; then
        url="http://carbide-static-pxe.forge/public/blobs/internal/$(uname -m)/scout.squashfs"
      fi

      # Staying in the loader is a supported debugging mode, not a failure.
      if [ "$url" = "none" ]; then
        echo "LOADER: newrootfs=none, staying in the loader"
        exit 0
      fi

      # The digest is extended into PCR 16 so an attestation can tell which
      # root filesystem a machine actually booted. Which bank exists depends on
      # the TPM, and a machine without one still boots — unmeasured.
      hash_cmd=""
      hash_alg=""
      if [ -e "/sys/class/tpm/tpm0/pcr-sha256/$PCR" ]; then
        hash_alg=sha256; hash_cmd=sha256sum
      elif [ -e "/sys/class/tpm/tpm0/pcr-sha384/$PCR" ]; then
        hash_alg=sha384; hash_cmd=sha384sum
      fi

      # The sidecar names the system to start. Fetched before the image so a
      # missing or truncated one fails in a second rather than after a
      # gigabyte and a half.
      system_url="''${url%.squashfs}.nixos-system"

      echo "LOADER: fetching $url"
      until [ -f "$NEXTROOT/.ready" ]; do
        if ! nixos_system=$(curl -sSf --retry 3 "$system_url"); then
          echo "LOADER: cannot read $system_url, retrying" >&2
          sleep 1
          continue
        fi

        # Recorded for check-scout-updates, which compares it against what the
        # server serves later to decide whether a newer image exists.
        if ! curl -sSf --head "$url" | sed 's/\r//' > /run/rootfs_info.txt; then
          echo "LOADER: cannot HEAD $url, retrying" >&2
          sleep 1
          continue
        fi

        if ! curl -sSf --retry 3 -o "$IMAGE" "$url"; then
          echo "LOADER: download failed, retrying" >&2
          sleep 1
          continue
        fi

        if [ -n "$hash_cmd" ]; then
          digest=$("$hash_cmd" "$IMAGE" | awk '{print $1}')
          echo "LOADER: measuring into PCR $hash_alg/$PCR"
          tpm2_pcrextend "$PCR:$hash_alg=$digest" || \
            echo "LOADER: PCR extend failed, continuing unmeasured" >&2
        else
          echo "LOADER: no PCR $PCR bank found; continuing unmeasured" >&2
        fi

        # The new root is a tmpfs — NixOS builds /etc and the rest into it at
        # boot — with only the store coming from the fetched image.
        mkdir -p "$NEXTROOT"
        mountpoint -q "$NEXTROOT" || mount -t tmpfs -o mode=0755 tmpfs "$NEXTROOT"
        mkdir -p "$NEXTROOT/nix/.ro-store" "$NEXTROOT/nix/.rw-store" "$NEXTROOT/nix/store"

        mount -t squashfs -o loop,ro "$IMAGE" "$NEXTROOT/nix/.ro-store"
        mount -t tmpfs -o mode=0755 tmpfs "$NEXTROOT/nix/.rw-store"
        # upperdir and workdir have to share a filesystem, hence both under
        # .rw-store rather than one of them in the root tmpfs.
        mkdir -p "$NEXTROOT/nix/.rw-store/store" "$NEXTROOT/nix/.rw-store/work"
        mount -t overlay overlay \
          -o "lowerdir=$NEXTROOT/nix/.ro-store,upperdir=$NEXTROOT/nix/.rw-store/store,workdir=$NEXTROOT/nix/.rw-store/work" \
          "$NEXTROOT/nix/store"

        # Catching this here turns a mismatched sidecar into a clear message
        # instead of a soft-reboot into a root with no init.
        if [ ! -e "$NEXTROOT$nixos_system/init" ]; then
          echo "LOADER: $nixos_system is not in the fetched store" >&2
          umount -R "$NEXTROOT" || true
          sleep 1
          continue
        fi

        # soft-reboot looks for an init in the new root. The absolute store
        # path is correct once the switch has happened and that path is real.
        mkdir -p "$NEXTROOT/sbin"
        ln -sf "$nixos_system/init" "$NEXTROOT/sbin/init"

        cp /run/rootfs_info.txt "$NEXTROOT/rootfs_info.txt"
        touch "$NEXTROOT/.ready"
      done

      echo "LOADER: switching into $nixos_system"
      systemctl soft-reboot
    '';
  };

  system.stateVersion = lib.mkDefault "25.11";
}
