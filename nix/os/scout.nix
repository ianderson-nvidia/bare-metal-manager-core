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
  mftX86 = import ../third-party/mft-x86_64.nix { inherit pkgs; };

  # mkosi.extra/usr/local/sbin/ipmitool, which shadows the real binary by
  # sitting earlier on PATH. `lan print` is rerouted to freeipmi's bmc-config
  # because ipmitool returns garbage for it on some BMCs; everything else
  # passes through. forge-scout calls plain `ipmitool` and depends on getting
  # this behaviour.
  #
  # Nix has no /usr/local/sbin to exploit, so the shadowing is done with
  # hiPrio: the wrapper and the real package both provide bin/ipmitool, and
  # priority decides which one lands in the system profile.
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
  imports = [
    # Gives us system.build.kernel and system.build.netbootRamdisk, where the
    # ramdisk carries a squashfs of the store. This is the piece that makes a
    # single-file boot artifact possible.
    (modulesPath + "/installer/netboot/netboot-minimal.nix")
  ];

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
  # Scout never evaluates Nix expressions; it only runs the closure it booted
  # with. Dropping the daemon and its channel machinery removes Nix itself.
  nix.enable = false;
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
    mftX86
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

  # Serial matters more than VGA here: these machines are in racks and the
  # console is reached over IPMI SOL. Both are enabled so either works.
  boot.kernelParams = [
    "console=tty0"
    "console=ttyS0,115200"
  ];

  # ConnectX and NVMe have to be probed before scout can report on them, and
  # the machines vary enough that guessing a module list is not viable.
  boot.initrd.includeDefaultModules = true;

  # ==========================================================================
  # Services
  # ==========================================================================

  # The netboot profile pulls in NetworkManager, which brings its own DHCP
  # handling and a sizeable closure. The mkosi image used systemd-networkd,
  # and mkosi.extra/etc/systemd/network/dhcp.network matched only wired
  # interfaces by name — a machine with a management NIC it should not be
  # DHCPing on is the reason that Match exists.
  networking.networkmanager.enable = lib.mkForce false;
  networking.wireless.enable = lib.mkForce false;
  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  networking.hostName = "scout";

  systemd.network.networks."10-dhcp" = {
    matchConfig.Name = "enx* enp* enP*";
    networkConfig.DHCP = "yes";
    # The BMC hands out reservations by MAC, so the client identifier has to
    # be the MAC rather than systemd's default DUID.
    dhcpV4Config.ClientIdentifier = "mac";
  };

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

  # Modules disabled in mkosi.extra/etc/modprobe.d/disable-mods.conf. These are
  # network protocol and crypto modules with a history of CVEs that scout has
  # no use for; blacklisting only stops autoloading by alias, whereas `install
  # ... /bin/false` stops an explicit modprobe too.
  boot.extraModprobeConfig = ''
    install algif_aead /bin/false
    install esp4 /bin/false
    install esp6 /bin/false
    install rxrpc /bin/false
    install rds /bin/false
    install rds_tcp /bin/false
  '';

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
  # rather than run the one it booted with indefinitely. The original compares
  # the Last-Modified of the served rootfs against a value the scout-loader
  # wrote to /rootfs_info.txt when it fetched it.
  #
  # There is no loader here — iPXE hands the artifacts straight to the kernel
  # and nothing in userspace sees the fetch — so the baseline is recorded on
  # first boot instead. The difference is a small race: an image published
  # between iPXE fetching and this unit running is recorded as current and
  # missed until the next one. That is a day's staleness at worst, against a
  # timer that only fires after 24 hours of uptime anyway.
  #
  # Polls the same artifact the loader fetched, so the URL is derived the same
  # way — see nix/os/scout-loader.nix.
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
    ];
    serviceConfig.Type = "oneshot";
    script = ''
      set -u
      STATE=/run/forge/scout-rootfs-info
      MIN_UPTIME=86400

      uptime=$(cut -d. -f1 /proc/uptime)
      if [ "$uptime" -lt "$MIN_UPTIME" ]; then
        echo "min uptime not reached ($uptime < $MIN_UPTIME)"
        exit 0
      fi

      pxe_uri=$(sed 's/ /\n/g' /proc/cmdline | grep '^pxe_uri=' | cut -d= -f2 || true)
      base=''${pxe_uri:-http://carbide-static-pxe.forge}
      # Must match what the loader fetched, including the newrootfs= override,
      # or this compares the published default against an image the machine
      # never booted and reboots in a loop.
      url=$(sed 's/ /\n/g' /proc/cmdline | grep '^newrootfs=' | cut -d= -f2- | tail -1 || true)
      if [ -z "$url" ] || [ "$url" = "none" ]; then
        url="$base/public/blobs/internal/$(uname -m)/scout.squashfs"
      fi

      current=$(curl -sf --head "$url" | sed 's/\r//' | grep -i '^Last-Modified:' || true)
      if [ -z "$current" ]; then
        echo "unable to read Last-Modified for $url" >&2
        exit 1
      fi

      mkdir -p /run/forge
      if [ ! -f "$STATE" ]; then
        echo "$current" > "$STATE"
        echo "recorded booted image as: $current"
        exit 0
      fi

      if [ "$current" != "$(cat "$STATE")" ]; then
        echo "newer scout available, rebooting"
        systemctl reboot
      fi
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
