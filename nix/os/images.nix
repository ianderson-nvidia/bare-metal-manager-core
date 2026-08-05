# The boot image matrix: architectures × roles.
#
# This is the only file that enumerates architectures. Everything under
# nix/os/ is arch-blind and learns its target from nixpkgs.hostPlatform;
# everything under nix/third-party/ learns it from stdenv.hostPlatform. Adding
# an architecture is an entry in `targets`, and adding an image is an entry in
# `roles` — neither requires touching flake.nix.
#
# Three roles, in two shapes:
#
#   scout-kexec   the discovery environment. Published as kernel + initrd +
#                 command line, because the loader kexecs into it; see
#                 nix/os/scout-kexec.nix for why it is not a squashfs.
#   scout-loader  the small image iPXE boots, which fetches the above.
#   qcow-imager   writes a customer qcow2 onto local disk. Chained directly by
#                 iPXE — no loader stage, because the work is one short pass.
#
# The last two are UKIs: one file holding kernel, initrd and command line,
# which is what lets iPXE boot them with a plain `kernel <url>` line.
{
  nixpkgs,
  lib,
  # Always the system doing the building. When it differs from a target, that
  # target is cross-compiled; when it matches, the build is native. Evaluating
  # this file on an aarch64 host is what produces native aarch64 images — see
  # the `just image-aarch64` recipes.
  buildSystem,
  # carbide's version string, written into scout's /etc/scout-image-version.
  version,
  # target attrs -> the forge-scout derivation built for that target. Comes
  # from crane, which is outside pkgs, so it cannot be resolved by callPackage
  # and has to be threaded in.
  forgeScoutFor,
}:

let
  roles = {
    scout-kexec = {
      modules = [
        ./scout.nix
        ./scout-nvidia.nix
      ];
      # Published as scout.kernel / scout.initrd / scout.cmdline, so the
      # webroot names match what crates/ipxe-renderer expects to serve.
      outputName = "scout";
      builder = "kexec";
      # The only role that needs a binary from outside its own package set.
      needsForgeScout = true;
    };

    scout-loader = {
      modules = [ ./scout-loader.nix ];
      outputName = "scout-loader";
      builder = "uki";
    };

    qcow-imager = {
      modules = [ ./qcow-imager.nix ];
      outputName = "qcow-imager";
      builder = "uki";
    };
  };

  # `roles` per target rather than a full cross-product, so that an
  # architecture which cannot yet produce an image says so here instead of
  # leaving a broken attribute nobody notices until CI runs. Both targets are
  # currently square; the list is kept because the asymmetry is the normal
  # state during a port, not the exception.
  targets = {
    x86_64 = {
      system = "x86_64-linux";
      roles = [
        "scout-kexec"
        "scout-loader"
        "qcow-imager"
      ];
    };
    aarch64 = {
      system = "aarch64-linux";
      roles = [
        "scout-kexec"
        "scout-loader"
        "qcow-imager"
      ];
    };
  };

  # x86_64 keeps the unsuffixed names that the justfile and pxe/Makefile.toml
  # already reference; aarch64 takes the -aarch64 suffix used elsewhere in this
  # flake (ipxe-efi-aarch64, carbide-scout-aarch64, rest-api-*-aarch64).
  attrNameFor = targetName: roleName: if targetName == "x86_64" then roleName else "${roleName}-aarch64";

  evalRole =
    targetName: target: roleName:
    let
      role = roles.${roleName};
    in
    nixpkgs.lib.nixosSystem {
      specialArgs = lib.optionalAttrs (role.needsForgeScout or false) {
        forgeScout = forgeScoutFor target;
        scoutVersion = version;
      };
      modules =
        role.modules
        ++ [ { nixpkgs.hostPlatform = target.system; } ]
        # Only stated when it differs. Setting buildPlatform to the host's own
        # system is a no-op in principle, but leaving it off entirely keeps the
        # native evaluation byte-identical to what it was before this file
        # existed, which is what makes the refactor checkable.
        ++ lib.optional (target.system != buildSystem) { nixpkgs.buildPlatform = buildSystem; };
    };

  # { x86_64 = { scout-kexec = <system>; ... }; aarch64 = { ... }; }
  systems = lib.mapAttrs (
    targetName: target:
    lib.genAttrs target.roles (roleName: evalRole targetName target roleName)
  ) targets;

  # Both builders take the same shape — an evaluated system and an output name
  # — and derive their package set from the system rather than accepting one,
  # so a cross-built image cannot be packed by native tooling. See the note in
  # nix/os/uki.nix about the x86 stub that would otherwise wrap an aarch64
  # kernel.
  buildArtifact =
    roleName: nixosSystem:
    let
      role = roles.${roleName};
      args = {
        inherit nixosSystem;
        name = role.outputName;
      };
    in
    if role.builder == "uki" then import ./uki.nix args else import ./scout-kexec.nix args;
in

{
  # Exposed so callers can reach config.system.build.* — the boot-artifacts
  # payload needs scout's toplevel to build a binary cache from it.
  inherit systems;

  # Flat, ready to merge into the flake's packages: scout-kexec, scout-loader,
  # qcow-imager, scout-loader-aarch64, qcow-imager-aarch64.
  packages = lib.concatMapAttrs (
    targetName: roleSet:
    lib.mapAttrs' (
      roleName: nixosSystem:
      lib.nameValuePair (attrNameFor targetName roleName) (buildArtifact roleName nixosSystem)
    ) roleSet
  ) systems;
}
