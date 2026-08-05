# Pack a NixOS netboot system into a single Unified Kernel Image.
#
# A UKI is one PE binary holding the kernel, the initrd, and the kernel
# command line, all behind systemd-stub. iPXE loads it with a plain
# `kernel <url>` line, which is what lets this drop into the existing boot
# chain unchanged: carbide-pxe keeps rendering
#
#   kernel {{base_url}}/internal/x86_64/scout.efi machine_id=… server_uri=…
#
# against a stable filename. Serving the kernel and initrd separately would
# work too, but NixOS needs `init=/nix/store/<hash>-nixos-system-…/init` on
# the command line, and that hash changes with every rebuild — carbide-pxe
# would have to be taught the current store path on each scout release.
# Embedding the command line at build time keeps that coupling out of the
# provisioning service.
#
# Values carbide-pxe appends at boot are still honoured: systemd-stub
# concatenates the command line it was passed onto the embedded one. That
# stops being true under secure boot, where the stub ignores an unsigned
# external command line unless signed addons are configured — worth knowing
# before measured boot becomes enforcing, because the per-machine parameters
# are what would silently stop arriving.
{
  # An evaluated NixOS configuration; supplies system.build.* and the package
  # set the image is built from.
  nixosSystem,
  # Bare name of the output, e.g. "scout" -> scout.efi.
  name,
}:

let
  # pkgs comes from the system rather than as an argument. Taking both invites
  # them to disagree, and the failure is silent: a native pkgs with a
  # cross-built system picks the x86 stub for an aarch64 kernel, producing a
  # UKI the firmware rejects without saying why.
  inherit (nixosSystem) config pkgs;

  # netbootRamdisk is the initrd with the store squashfs inside it, so the
  # machine needs nothing beyond this one file.
  kernel = "${config.system.build.kernel}/${pkgs.stdenv.hostPlatform.linux-kernel.target}";
  initrd = "${config.system.build.netbootRamdisk}/initrd";

  # `init=` is what tells stage-1 which system generation to activate, and it
  # is the reason this has to be baked in rather than supplied by carbide-pxe.
  cmdline = pkgs.lib.concatStringsSep " " (
    [ "init=${config.system.build.toplevel}/init" ] ++ config.boot.kernelParams
  );

  # The EFI architecture suffix in the stub filename is the target's, not the
  # builder's, so cross-built aarch64 images pick up linuxaa64.efi.stub.
  efiArch = pkgs.stdenv.hostPlatform.efiArch;

  # ukify embeds an .osrel section, and looks for /usr/lib/os-release to fill
  # it. That path does not exist in the build sandbox, so point it at the one
  # this configuration generates. Beyond satisfying ukify, the section is what
  # `bootctl` and systemd-boot read to label the entry, so it wants to be the
  # image's own os-release rather than the builder's.
  osRelease = config.environment.etc."os-release".source;
in

pkgs.runCommand "${name}-uki"
  {
    nativeBuildInputs = [ pkgs.systemdUkify ];
    meta.description = "Netbootable UKI for ${name}";
  }
  ''
    mkdir -p $out
    ukify build \
      --linux=${kernel} \
      --initrd=${initrd} \
      --cmdline=${pkgs.lib.escapeShellArg cmdline} \
      --os-release=@${osRelease} \
      --stub=${pkgs.systemd}/lib/systemd/boot/efi/linux${efiArch}.efi.stub \
      --output=$out/${name}.efi

    echo "UKI size: $(du -h $out/${name}.efi | cut -f1)"
  ''
