# The scout discovery environment, as a NixOS system.
#
# Scout is booted over the network by every machine carbide is asked to
# inventory. It runs entirely from RAM, reports what hardware it finds, and is
# discarded — nothing is installed and no disk is written. That shape is why
# this is a netboot configuration rather than a disk image: the whole system,
# including the Nix store, is packed into the initrd and handed to the machine
# in one file.
#
# carbide-pxe passes per-machine values on the kernel command line
# (machine_id, server_uri, cli_cmd, mac). See the forge-scout-pre service
# below for how those reach the agent.
{
  config,
  lib,
  pkgs,
  modulesPath,
  forgeScout,
  # carbide's version string, written to /etc/scout-image-version so a booted
  # machine can be traced back to the image it came from. The mkosi postinst
  # wrote PKG_VERSION here for the same reason.
  scoutVersion,
  ...
}:

let
  # NVIDIA's Mellanox Firmware Tools. Distinct from nixpkgs' mstflint — see the
  # note beside both in environment.systemPackages.
  # Arch is read from stdenv inside the derivation, so this one call serves
  # both the x86 and the aarch64 scout without the module knowing which.
  mft = pkgs.callPackage ../third-party/mft.nix { };

  # mkosi.extra/opt/forge/check-nvme-drives.sh — a predicate carbide calls to
  # decide whether a machine's disks are usable before provisioning it.
  # Exit status is the whole interface; the output is for the operator.
  checkNvmeDrives = pkgs.writeShellScriptBin "check-nvme-drives" ''
    nvme_devices=$(${pkgs.util-linux}/bin/lsblk -d -o NAME,TYPE,RO | grep -i nvme | grep disk)
    echo "$nvme_devices"

    readonly_nvme=$(echo "$nvme_devices" | grep '1$')
    if [ -n "$readonly_nvme" ]; then
      echo "Found read-only NVMe devices:" >&2
      echo "$readonly_nvme" >&2
      exit 1
    fi
    echo "All NVMe devices are writeable"
  '';

  # mkosi.extra/usr/local/bin/fixnvmero.sh — the remedy when the check above
  # fails. A namespace left read-only by a previous owner is recreated at full
  # capacity, which is destructive by design: it deletes the namespace and
  # everything on it. Run deliberately, never automatically.
  fixNvmeRo = pkgs.writeShellScriptBin "fixnvmero" ''
    devices=$(${pkgs.util-linux}/bin/lsblk -n | grep " 1 disk" | ${pkgs.gawk}/bin/awk '{print $1}')

    for dev in ''${devices}; do
      basedev=$(echo "$dev" | sed 's/n[0-9][0-9]*$//')
      ns=$(echo "$dev" | sed 's/.*n\([0-9][0-9]*\)$/\1/')
      bse=$(${pkgs.nvme-cli}/bin/nvme id-ns /dev/"''${dev}" | grep "in use" | ${pkgs.gawk}/bin/awk '{print $5}' | cut -d: -f2)
      bs=$((2 ** bse))
      cap=$(${pkgs.nvme-cli}/bin/nvme id-ns /dev/"''${dev}" | grep -i nvmcap | ${pkgs.gawk}/bin/awk '{print $NF}')
      capb=$((cap / bs))
      ctrl=$(${pkgs.nvme-cli}/bin/nvme id-ctrl /dev/"''${dev}" | grep "^cntlid" | ${pkgs.gawk}/bin/awk '{print $NF}')
      echo "Device ''${dev} capacity ''${cap} blocksize ''${bs} blocks ''${capb} controller ''${ctrl}"

      ${pkgs.nvme-cli}/bin/nvme delete-ns /dev/"''${basedev}" -n "''${ns}"
      ${pkgs.nvme-cli}/bin/nvme create-ns /dev/"''${basedev}" --nsze="''${capb}" --ncap="''${capb}" --flbas=0 -dps=0
      ${pkgs.nvme-cli}/bin/nvme attach-ns /dev/"''${basedev}" --namespace-id="''${ns}" -controllers="''${ctrl}"
      ${pkgs.nvme-cli}/bin/nvme ns-rescan /dev/"''${basedev}"
    done
  '';

  # mkosi.extra/usr/local/sbin/ipmitool, which shadows the real binary by
  # sitting earlier on PATH. `lan print` is rerouted to freeipmi's bmc-config
  # because ipmitool returns garbage for it on some BMCs; everything else
  # passes through. forge-scout calls plain `ipmitool` and depends on getting
  # this behaviour.
  #
  # Nix has no /usr/local/sbin to exploit, so the shadowing is done with
  # hiPrio: the wrapper and the real package both provide bin/ipmitool, and
  # priority decides which one lands in the system profile.
  ipmitoolWrapper = lib.hiPrio (
    pkgs.writeShellScriptBin "ipmitool" ''
      set -o pipefail
      if [ "$1" = "lan" ] && [ "$2" = "print" ]; then
        exec ${pkgs.freeipmi}/bin/bmc-config --checkout -S Lan_Conf \
          | ${pkgs.gawk}/bin/awk '/\tIP_Address / {print "IP Address              : " $2}; /\tMAC_Address / {print "MAC Address             : " $2}'
      else
        exec ${pkgs.ipmitool}/bin/ipmitool "$@"
      fi
    ''
  );
in

{
  # netboot.nix directly, not netboot-minimal.nix.
  #
  # The chain is netboot-minimal -> netboot-base -> netboot.nix plus
  # profiles/base.nix and profiles/installation-device.nix. Scout wants one
  # thing from that stack, hardware.enableAllHardware, and inherits a NixOS
  # installer to get it: a copy of nixpkgs via cd-dvd/channel.nix, vim, and
  # nixos-install, none of which a discovery image has any use for.
  #
  # netboot.nix on its own is the mechanism — squashfsStore, netbootRamdisk,
  # and the tmpfs-root / overlay-store layout that makes a single boot artifact
  # possible.
  imports = [
    (modulesPath + "/installer/netboot/netboot.nix")
    ./common/console.nix
    ./common/modprobe-hardening.nix
  ];

  # Scout inventories machines nobody enumerated in advance, so it needs
  # drivers for hardware it has never seen. netboot-base set this implicitly;
  # stating it here makes the breadth a decision rather than a side effect of
  # importing an installer.
  hardware.enableAllHardware = true;

  # Grace requires 64K pages, and nixpkgs sets no arm64 page size at all — it
  # takes the kernel's defconfig, which is 4K. The mkosi profile got this by
  # installing Ubuntu's linux-nvidia-64k-hwe-24.04; there is no prebuilt
  # equivalent here, so the option has to be set and the kernel rebuilt.
  #
  # This is expensive and the expense is unavoidable: a custom kernel config is
  # a derivation nobody upstream has built, so it never substitutes from
  # cache.nixos.org and is compiled on every empty store. Under binfmt
  # emulation that is a kernel compile under qemu, which is the strongest
  # argument in this tree for a real aarch64 builder — see
  # docs/nix-aarch64-builder-setup.md.
  #
  # Only scout. The loader and the qcow-imager keep the cached 4K kernel: the
  # loader hands off with kexec, so scout boots its *own* kernel rather than
  # inheriting this one, and the imager writes disks rather than driving GPUs.
  # That independence is precisely what soft-reboot could not have given us.
  #
  # It also makes the aarch64-page-size check in flake.nix load-bearing rather
  # than precautionary: with a 64K kernel, a binary whose PT_LOAD segments are
  # 4K-aligned genuinely fails to map.
  boot.kernelPackages = lib.mkIf pkgs.stdenv.hostPlatform.isAarch64 (
    pkgs.linuxPackagesFor (
      pkgs.linux.override {
        structuredExtraConfig = with lib.kernel; {
          ARM64_4K_PAGES = lib.mkForce no;
          ARM64_64K_PAGES = lib.mkForce yes;
        };
        # Fail loudly rather than silently falling back to a 4K kernel, which
        # would look identical from the outside and only surface as unmappable
        # binaries on real hardware.
        ignoreConfigErrors = false;
      }
    )
  );

  # netboot-minimal disabled this, and it was right to: linux-firmware is
  # 770 MB, over half the image. Enabling it on the reasoning that a device
  # which cannot load firmware fails to probe — and so goes unreported — cost
  # more than the entire rest of the closure.
  #
  # The mkosi image does not ship linux-firmware either, so this matches what
  # carbide runs today. If a specific NIC or controller turns out to need a
  # blob, add that firmware package rather than the whole set.
  hardware.enableRedistributableFirmware = lib.mkForce false;

  # The nixpkgs source (196 MB) is in the closure via /etc/nix/registry.json,
  # which nix.enable creates so `nix run nixpkgs#foo` resolves on a normal
  # machine. Scout evaluates nothing and only substitutes prebuilt closures, so
  # it is dead weight — but `nix.registry = lib.mkForce { }` is not the way to
  # drop it: setting that option makes the module system resolve registry
  # entries, which reaches out to GitHub for an unpinned flake and hangs the
  # build with no timeout. Try nix.settings.flake-registry = "" instead, and
  # test it on its own before believing the size number.

  # profiles/base.nix supplied a default package set — an editor and assorted
  # shell tooling. Scout names everything it uses below.
  environment.defaultPackages = lib.mkForce [ ];

  # ==========================================================================
  # Size reduction
  #
  # Every megabyte here is pulled over HTTP by each machine being discovered,
  # so the defaults that make sense for a workstation are all wrong. The
  # documentation, locale, and font sets are the expensive ones.
  # ==========================================================================
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
  fonts.fontconfig.enable = false;
  i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
  # Nix is enabled so a running scout can be updated by fetching the new
  # closure from a binary cache and activating it, rather than rebooting into
  # a whole new image:
  #
  #   nix copy --from <cache> "$new_system"
  #   "$new_system"/bin/switch-to-configuration switch
  #
  # `nix copy` consults the local store database and transfers only the paths
  # this machine is missing, so an agent-only rebuild moves megabytes instead
  # of the 1.4 GB image. The database is populated at boot by netboot.nix's
  # register-nix-paths unit, which is what makes the "only what is missing"
  # part work — without it the store looks empty and everything re-downloads.
  #
  # This costs almost nothing in size: nix, boost and icu4c are already in the
  # closure because that unit references config.nix.package regardless of this
  # option. `nix.enable` governs whether NixOS *configures* Nix, not whether
  # the package is present.
  #
  # Still to decide before this is usable: where the cache lives, and how it is
  # signed. Until then Nix is present and idle — nothing invokes it at boot.
  nix.enable = true;
  # No display and no input devices beyond a serial console. Mesa drags in
  # LLVM, which is one of the larger single items in a default closure.
  hardware.graphics.enable = false;
  services.speechd.enable = false;

  # The netboot profile enables ZFS because an installer might be asked to
  # create a pool. Scout only reads what is already on a disk, and the ZFS
  # kernel module plus its userland is one of the larger things it would
  # otherwise carry. Turning it off also settles the forceImportRoot warning,
  # which exists to stop an installer importing a pool that another machine
  # still has mounted — not a situation scout can create.
  boot.supportedFilesystems.zfs = lib.mkForce false;

  # ==========================================================================
  # Hardware discovery tooling
  #
  # Mirrors the package list in pxe/mkosi.profiles/scout-oss-x86_64/mkosi.conf.
  # Debian-isms with no equivalent here are deliberately absent: apt-utils,
  # debconf-i18n, debian-archive-keyring, keyboard-configuration, and the
  # lib*/-dev packages that only existed to satisfy dpkg.
  # ==========================================================================
  environment.systemPackages = with pkgs; [
    # Inventory: what is this machine?
    dmidecode
    lshw
    pciutils
    util-linux

    # Storage
    hdparm
    nvme-cli
    sg3_utils
    smartmontools
    erofs-utils

    # Out-of-band management. The wrapper must come with the real ipmitool,
    # which it execs into for everything but `lan print`.
    freeipmi
    ipmitool
    ipmitoolWrapper
    efibootmgr
    tpm2-tools

    # Networking and fabric. rdma-core provides the ibverbs utilities.
    #
    # Both Mellanox tool sets are present, because the scout image has both and
    # they do not overlap: mstflint supplies the mst* commands (mstconfig,
    # mstlink, mstfwreset, ...) while NVIDIA's MFT supplies flint, mst and the
    # mlx* suite. Dropping either loses roughly half the fabric tooling.
    bind.dnsutils
    ethtool
    iproute2
    iputils
    lldpd
    mstflint
    mft
    mtr
    netcat-openbsd
    nettools
    rdma-core
    tcpdump

    # Burn-in and benchmarking
    iperf3
    memtester
    stress-ng
    sysbench

    # Container runtime, for validation workloads shipped as images
    containerd
    runc

    # General shell environment
    curl
    file
    git
    gnutar
    python3
    tmux
    wget
    zstd

    # The agent itself, and the helpers it shells out to.
    forgeScout
    checkNvmeDrives
    fixNvmeRo
  ];

  # ==========================================================================
  # Boot and console
  # ==========================================================================

  # Serial console and the DHCP match come from nix/os/common/console.nix,
  # which every boot image imports.

  # ConnectX and NVMe have to be probed before scout can report on them, and
  # the machines vary enough that guessing a module list is not viable.
  boot.initrd.includeDefaultModules = true;

  # ==========================================================================
  # Services
  # ==========================================================================

  networking.hostName = "scout";

  # Enabled by 00-forge-discovery-image.preset in the mkosi image.
  services.timesyncd.enable = true;
  services.resolved.enable = true;

  services.lldpd = {
    enable = true;
    # -M 1 advertises this host as a Station, which is what carbide's LLDP
    # neighbour parsing expects to see from a machine under discovery.
    extraArgs = [
      "-M"
      "1"
    ];
  };

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "yes";
  };

  # From mkosi.extra/etc/sysusers.d/scout.conf. Present so that device nodes
  # and sockets owned by these groups get the ownership the tooling expects.
  users.groups.netdev = { };
  users.groups.lxd = { };

  # The disable-mods.conf blacklist lives in
  # nix/os/common/modprobe-hardening.nix.

  environment.etc."scout-image-version".text = "${scoutVersion}\n";

  # Root is left passwordless by the netboot profile, which is what makes a
  # failed discovery debuggable over IPMI serial. The mkosi profile set
  # RootPassword=password for the same reason. Not restated here: setting it
  # again only collides with the profile's own definition.

  # Counterpart of mkosi.extra/opt/forge/forge-scout-pre.sh.
  #
  # carbide-pxe renders each machine's identity into the kernel command line
  # rather than into the image, so one image serves every machine. Lifting
  # those values out is the obvious part; the rest of this unit is setup the
  # agent cannot do for itself.
  #
  # Paths under /opt/forge are kept as-is rather than moved somewhere more
  # Nix-shaped: forge-scout reads forge_root.pem from there, and changing the
  # layout would mean changing the agent in step with the image.
  systemd.services.forge-scout-pre = {
    description = "Prepare the scout environment before discovery";
    before = [ "forge-scout.service" ];
    requiredBy = [ "forge-scout.service" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    path = with pkgs; [
      curl
      kmod
      openssh
      systemd
      coreutils
    ];
    serviceConfig.Type = "oneshot";
    serviceConfig.RemainAfterExit = true;
    script = ''
      set -u
      mkdir -p /opt/forge

      # PATH here mirrors forge-scout.env.template, and the ordering is
      # load-bearing: /usr/local/sbin must precede the real ipmitool so the
      # bmc-config wrapper wins. Under Nix that shadowing is done by package
      # priority instead, but the agent still expects the variable set.
      cat > /opt/forge/forge-scout.env <<'ENVEOF'
      RUST_BACKTRACE=full
      RUST_LIB_BACKTRACE=0
      ENVEOF

      for param in $(cat /proc/cmdline); do
        case "$param" in
          machine_id=*|server_uri=*|cli_cmd=*|pxe_uri=*)
            echo "$param" >> /opt/forge/forge-scout.env
            ;;
        esac
      done

      # shellcheck disable=SC1091
      . /opt/forge/forge-scout.env

      # carbide signs its API with a private CA, so scout has to hold the root
      # before it can talk to the server at all. pxe_uri overrides the default
      # for machines on networks that cannot resolve the internal hostname.
      #
      # Failing here aborts the unit, and forge-scout does not start. That is
      # deliberate: the mkosi image also carries a forge_root.pem, but it is a
      # self-signed CN=site-root that expired in February 2024 — a leftover, not
      # a fallback. Nothing here is worth falling back to, and a scout that
      # proceeds without a CA fails later with TLS errors that point at the
      # server rather than at the missing certificate.
      if ! curl --retry 5 --retry-all-errors -sSf \
             -o /opt/forge/forge_root.pem \
             "''${pxe_uri:-http://carbide-pxe.forge}/api/v0/tls/root_ca"; then
        echo "failed to fetch the carbide root CA; refusing to start discovery" >&2
        exit 1
      fi

      # carbide reaches back into the booted machine over SSH during
      # discovery, so the keypair has to exist before the agent announces
      # itself. Generated per boot — scout is ephemeral and the key must not
      # be baked into an image every machine shares.
      mkdir -p /root/.ssh
      if [ ! -f /root/.ssh/privatekey.pem ]; then
        ssh-keygen -t rsa -b 4096 -f /root/.ssh/privatekey.pem -q -N ""
        ssh-keyscan -p 22 127.0.0.1 > /root/.ssh/known_hosts
        cat /root/.ssh/privatekey.pem.pub >> /root/.ssh/authorized_keys
      fi

      # mlx5_ib loaded during early boot can miss devices that were still
      # resetting. Reloading once the bus has settled is what makes ConnectX
      # cards appear in the inventory reliably.
      rmmod mlx5_ib || true
      udevadm settle
      modprobe mlx5_ib || true
      udevadm settle

      # load_modules.sh. Re-firing `add` on every PCI device makes the kernel
      # rerun the driver match now that mlx5_ib is back, which is what pulls in
      # drivers for cards that lost their binding during the reload above.
      udevadm trigger --wait-daemon --type=devices --subsystem-match=pci --action=add --settle

      # etc/init.d/forge-init. nvssh refuses to run when / is world-writable,
      # and the netboot tmpfs root is created 0777.
      chmod o-w /
    '';
  };

  # pxe/common_files/check-scout-updates.{sh,service,timer}.
  #
  # A machine that sits in discovery for days should pick up a rebuilt scout
  # rather than run the one it booted with indefinitely.
  #
  # The original compares the Last-Modified header of the served rootfs against
  # a copy the loader saved at fetch time. That works, but it is a proxy: an
  # image republished with identical contents gets a new timestamp and reboots
  # the fleet for nothing, and a server that does not set the header at all
  # makes the check fail open.
  #
  # A NixOS system has a better answer to "am I current". Its store path is a
  # hash of the entire closure, the running system knows it as
  # /run/current-system, and scout-kexec publishes the same path beside the
  # initrd, inside the command line it ships as `init=<toplevel>/init`.
  # Comparing those two strings is exact in both directions: equal means
  # byte-identical systems, different means genuinely different. It also needs
  # nothing from the loader, which removes the one piece of state the two had
  # to agree on.
  #
  # Reboot remains the remedy. With nix.enable = true the closure could instead
  # be fetched and activated in place with switch-to-configuration, which is
  # the reason Nix is enabled — but that needs a binary cache to fetch from,
  # and a kernel or driver change forces a reboot regardless.
  systemd.services.check-scout-updates = {
    description = "Reboot if a newer scout image has been published";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    path = with pkgs; [
      curl
      coreutils
      gnused
      gnugrep
      systemd
      # `nix copy` fetches the new closure; config.nix.package rather than
      # pkgs.nix so it is the same nix the rest of the system is configured
      # with, and so this unit does not pin a second copy into the closure.
      config.nix.package
    ];
    serviceConfig.Type = "oneshot";
    script = ''
      set -u
      MIN_UPTIME=86400

      # Long enough that a machine part-way through discovery is not rebooted
      # out from under whatever asked for it.
      uptime=$(cut -d. -f1 /proc/uptime)
      if [ "$uptime" -lt "$MIN_UPTIME" ]; then
        echo "min uptime not reached ($uptime < $MIN_UPTIME)"
        exit 0
      fi

      pxe_uri=$(sed 's/ /\n/g' /proc/cmdline | grep '^pxe_uri=' | cut -d= -f2 || true)
      base=''${pxe_uri:-http://carbide-static-pxe.forge}

      # Derived exactly as the loader derives it, newrootfs= override included,
      # or this compares against an image the machine never booted.
      url=$(sed 's/ /\n/g' /proc/cmdline | grep '^newrootfs=' | cut -d= -f2- | tail -1 || true)
      if [ -z "$url" ] || [ "$url" = "none" ]; then
        url="$base/public/blobs/internal/$(uname -m)/scout.initrd"
      fi

      cache="$base/public/blobs/internal/$(uname -m)/cache"
      # The published command line starts with init=<toplevel>/init, so the
      # system path is the first field with its prefix and suffix trimmed.
      # Read from the same file the loader boots with rather than a separate
      # sidecar, so there is nothing that can disagree with what was booted.
      published=$(curl -sf "''${url%.initrd}.cmdline" \
        | sed 's/ .*//; s|^init=||; s|/init$||' || true)
      if [ -z "$published" ]; then
        echo "unable to read the published system path for $url" >&2
        exit 1
      fi

      running=$(readlink -f /run/current-system)
      if [ "$running" = "$published" ]; then
        exit 0
      fi

      echo "newer scout published: $published (running $running)"

      # Fetch only what this machine is missing. The store database, loaded at
      # boot by register-nix-paths, is what lets nix skip everything already
      # present — for an agent-only rebuild that is a handful of paths rather
      # than the whole 1.4 GB image.
      #
      # --no-check-sigs because the cache is unsigned, and a signing key alone
      # will not change that. The cache in the boot-artifacts payload is built
      # by pkgs.mkBinaryCache, which has no signing support at all: its
      # make-binary-cache.py emits StorePath/URL/Compression/FileHash/FileSize/
      # NarHash/NarSize/References and never a Sig line. Pre-signing the store
      # paths does not help either — exportReferencesGraph, which is how that
      # derivation learns the closure, does not carry signatures.
      #
      # Producing a signed cache means building it with `nix copy --to file://`
      # after `nix store sign --recursive`, which cannot happen inside a
      # derivation because the private key would land in the store. That makes
      # it a staged artifact rather than a derivation-assembled one — the same
      # seam as the rest of the boot payload. See SESSION.md.
      if ! nix --extra-experimental-features nix-command \
             copy --no-check-sigs --from "$cache" "$published"; then
        echo "unable to fetch $published from $cache; rebooting instead" >&2
        systemctl reboot
        exit 0
      fi

      # A new kernel or initrd cannot be activated in place. Comparing against
      # /run/booted-system rather than /run/current-system is deliberate: it
      # answers "does what is running on the CPU differ", which stays correct
      # across an earlier live switch.
      if [ "$(readlink -f /run/booted-system/kernel)" != "$(readlink -f "$published/kernel")" ] ||
         [ "$(readlink -f /run/booted-system/initrd)" != "$(readlink -f "$published/initrd")" ]; then
        echo "kernel or initrd changed; rebooting to activate"
        systemctl reboot
        exit 0
      fi

      # Restarts every unit whose definition changed. forge-scout.service names
      # the agent by store path, so a new agent is a changed unit and gets
      # restarted without anything having to declare that dependency.
      "$published"/bin/switch-to-configuration switch
    '';
  };

  systemd.timers.check-scout-updates = {
    description = "Run the scout update check daily";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "daily";
      Persistent = true;
    };
  };

  systemd.services.forge-scout = {
    description = "Forge scout hardware discovery";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      EnvironmentFile = "/run/forge/forge-scout.env";
      ExecStart = "${forgeScout}/bin/forge-scout";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
