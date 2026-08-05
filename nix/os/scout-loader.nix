# The scout loader, as a NixOS system.
#
# Counterpart of the scout-loader mkosi profile. iPXE boots this small image;
# it fetches the much larger scout over HTTP, measures it into the TPM and
# kexecs into it. Keeping the two stages separate is what keeps the iPXE
# transfer down to tens of megabytes — the ~1.5 GB fetch happens from Linux
# userspace, where it can retry, report progress and pick a URL at runtime.
#
# Behaviour follows pxe/common_files/scout-loader-rclocal:
#
#   newrootfs=<url>   override the image to fetch
#   newrootfs=none    stay in the loader, for debugging
#   console=...       every console on the cmdline gets progress messages
#   PCR 16            extended with the digest of what was fetched
#
# Where it differs is the hand-off. mkosi's loader mounted an Ubuntu root
# filesystem and soft-rebooted into it; that works because such an image is a
# complete tree with a populated /etc. A NixOS image is not: its store holds
# every unit, but /etc is materialised by the toplevel's activation, which runs
# from stage 1. Soft-rebooting into a store leaves systemd with no units at all.
#
# So scout ships as a kernel and initrd and is kexec'd, which is the ordinary
# NixOS boot path. That also keeps scout on its *own* kernel: a soft-reboot
# never restarts the kernel, so scout would have inherited this image's, and its
# NVIDIA modules are built against one specific version. See nix/os/scout-kexec.nix.
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
    kexec-tools
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
    ./common/console.nix
    ./common/modprobe-hardening.nix
  ];

  # ==========================================================================
  # Keep it small
  #
  # This image is what iPXE transfers, so its size is the cost paid before a
  # machine can do anything. It holds no discovery tooling, no GPU stack and no
  # agent — only enough to fetch scout and kexec into it.
  # ==========================================================================
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
  fonts.fontconfig.enable = false;
  i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
  # The loader fetches scout and kexecs into it. It never evaluates a
  # derivation, never substitutes a path, and never rebuilds itself, so there
  # is nothing for Nix to do here.
  #
  # scout.nix sets this true, because a running scout updates itself with
  # `nix copy`. That difference is deliberate and not worth making uniform:
  # enabling it here pulled the nixpkgs source in through the flake registry
  # and added about 100 MB to the artifact iPXE transfers to every machine.
  #
  # nix, boost and icu4c remain in the closure regardless — netboot.nix's
  # register-nix-paths references config.nix.package whether Nix is enabled or
  # not. This option governs configuration, not closure membership.
  nix.enable = false;
  hardware.graphics.enable = false;
  services.speechd.enable = false;
  boot.supportedFilesystems.zfs = lib.mkForce false;

  # Console, networkd and the DHCP match come from
  # nix/os/common/console.nix.
  networking.hostName = "scout-loader";

  # Stage 1 here mounts a squashfs out of the initramfs and nothing else — no
  # disk, no network, no encryption. The default module set exists for booting
  # off unknown storage controllers, which never happens in this image.
  boot.initrd.includeDefaultModules = false;

  # Nothing beyond what stage 1 already loads: the fetched image is handed to
  # kexec as two files rather than mounted, so there is no loop, squashfs or
  # overlay involved. The NIC driver is bound by udev from the full module
  # tree, which ships with the kernel regardless.

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
    description = "Fetch scout and kexec into it";
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
      KERNEL=/run/scout.kernel
      INITRD=/run/scout.initrd
      CMDLINE=/run/scout.cmdline

      cmdline_value() {
        sed 's/ /\n/g' /proc/cmdline | grep "^$1=" | cut -d= -f2- | tail -1
      }

      # newrootfs names the initrd; the kernel and command line sit beside it.
      # Keeping one parameter means the existing loader-rootfs iPXE template
      # and any hand-written newrootfs= keep working unchanged.
      url=$(cmdline_value newrootfs)
      if [ -z "$url" ]; then
        url="http://carbide-static-pxe.forge/public/blobs/internal/$(uname -m)/scout.initrd"
      fi

      # Staying in the loader is a supported debugging mode, not a failure.
      if [ "$url" = "none" ]; then
        echo "LOADER: newrootfs=none, staying in the loader"
        exit 0
      fi

      base="''${url%.initrd}"
      kernel_url="$base.kernel"
      cmdline_url="$base.cmdline"

      # The digest is extended into PCR 16 so an attestation can tell which
      # scout a machine actually booted. Which bank exists depends on the TPM,
      # and a machine without one still boots — unmeasured.
      hash_cmd=""
      hash_alg=""
      if [ -e "/sys/class/tpm/tpm0/pcr-sha256/$PCR" ]; then
        hash_alg=sha256; hash_cmd=sha256sum
      elif [ -e "/sys/class/tpm/tpm0/pcr-sha384/$PCR" ]; then
        hash_alg=sha384; hash_cmd=sha384sum
      fi

      echo "LOADER: fetching $url"
      until [ -f /run/scout.ready ]; do
        # Small files first, so a webroot that is missing one of the three
        # fails in a second rather than after a gigabyte and a half.
        if ! curl -sSf --retry 3 -o "$CMDLINE" "$cmdline_url"; then
          echo "LOADER: cannot read $cmdline_url, retrying" >&2
          sleep 1
          continue
        fi

        if ! curl -sSf --retry 3 -o "$KERNEL" "$kernel_url"; then
          echo "LOADER: kernel download failed, retrying" >&2
          sleep 1
          continue
        fi

        if ! curl -sSf --retry 3 -o "$INITRD" "$url"; then
          echo "LOADER: initrd download failed, retrying" >&2
          sleep 1
          continue
        fi

        touch /run/scout.ready
      done

      # The initrd carries the entire Nix store, so its digest identifies the
      # scout being booted as precisely as the squashfs digest used to.
      if [ -n "$hash_cmd" ]; then
        digest=$("$hash_cmd" "$INITRD" | awk '{print $1}')
        echo "LOADER: measuring into PCR $hash_alg/$PCR"
        tpm2_pcrextend "$PCR:$hash_alg=$digest" || \
          echo "LOADER: PCR extend failed, continuing unmeasured" >&2
      else
        echo "LOADER: no PCR $PCR bank found; continuing unmeasured" >&2
      fi

      # Per-machine parameters are rendered onto *this* image's command line by
      # carbide-pxe, and scout needs them too — machine_id and server_uri are
      # what let forge-scout report in at all. They are carried across rather
      # than re-derived, because the loader has no other source for them.
      #
      # Dropped: newrootfs, because scout has no loader to run and leaving it
      # would be misleading in /proc/cmdline on a booted machine; and init,
      # initrd and BOOT_IMAGE, which describe *this* image and would send scout
      # to the wrong toplevel.
      #
      # Everything else is appended even when scout's own command line already
      # sets it, which duplicates console= and root=. That is deliberate rather
      # than sloppy. The kernel enables every console= it is given and makes the
      # last one /dev/console, so appending the machine's console after scout's
      # defaults is what lets carbide-pxe pick the right serial port per machine
      # while keeping the defaults live — the same "every console on the cmdline
      # gets messages" behaviour the mkosi loader had. Deduplicating by key
      # would silently discard exactly the value that matters most.
      passthrough=""
      for arg in $(cat /proc/cmdline); do
        case "$arg" in
          newrootfs=*|init=*|initrd=*|BOOT_IMAGE=*) ;;
          *) passthrough="$passthrough $arg" ;;
        esac
      done

      scout_cmdline="$(cat "$CMDLINE")$passthrough"

      echo "LOADER: kexec into $(sed 's/ .*//' "$CMDLINE")"
      kexec --load "$KERNEL" --initrd="$INITRD" --command-line "$scout_cmdline"
      kexec -e
    '';
  };

  system.stateVersion = lib.mkDefault "25.11";
}
