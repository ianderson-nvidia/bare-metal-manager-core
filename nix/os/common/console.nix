# Console and network settings shared by every boot image.
#
# scout, the scout loader and the qcow-imager all boot on racked machines that
# nobody has a keyboard in front of, so they need the same two things: a serial
# console that carbide-pxe's rendered command line can reach, and a DHCP client
# that only speaks on the interfaces it should.
#
# This is the one file in nix/os that looks at the target architecture, and it
# does so for a single reason spelled out below. Everything else is arch-blind
# and learns its target from nixpkgs.hostPlatform.
{ lib, pkgs, ... }:

{
  # Serial matters more than VGA here: these machines are in racks and the
  # console is reached over IPMI SOL. Both are enabled so either works.
  #
  # ttyAMA0 is the PL011 UART on aarch64 server platforms. It is not merely a
  # nicety there: pxe/common_files/disk_imaging.sh probes ttyS0, ttyS1 and
  # ttyAMA0 and writes its progress to the first that works, so on a machine
  # where the kernel never brought ttyAMA0 up the imager silently falls back
  # and the operator sees nothing.
  boot.kernelParams = [
    "console=tty0"
    "console=ttyS0,115200"
  ]
  ++ lib.optionals pkgs.stdenv.hostPlatform.isAarch64 [
    "console=ttyAMA0,115200"
  ];

  # The netboot profile pulls in NetworkManager, which brings its own DHCP
  # handling and a sizeable closure. The mkosi images used systemd-networkd,
  # and mkosi.extra/etc/systemd/network/dhcp.network matched only wired
  # interfaces by name — a machine with a management NIC it should not be
  # DHCPing on is the reason that Match exists.
  networking.networkmanager.enable = lib.mkForce false;
  networking.wireless.enable = lib.mkForce false;
  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;

  systemd.network.networks."10-dhcp" = {
    # enP* is the predictable name aarch64 platforms produce for on-board NICs
    # enumerated through ACPI, so this pattern already covers both
    # architectures.
    matchConfig.Name = "enx* enp* enP*";
    networkConfig.DHCP = "yes";
    # The BMC hands out reservations by MAC, so the client identifier has to
    # be the MAC rather than systemd's default DUID.
    dhcpV4Config.ClientIdentifier = "mac";
  };
}
