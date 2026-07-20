{
  pkgs,
  mkDebPackage,
  # Native x86_64 Rust binary attrset — provides carbide-scout for the amd64 deb.
  nativeRustBinaries,
  # aarch64 carbide-scout binary — provides the arm64 deb.
  carbideScoutAarch64,
  # Paths to service files relative to the repo root, resolved in flake.nix so
  # they refer to the actual repo checkout rather than this library file's
  # location in the Nix store.
  forgeScoutServiceFile,
  forgeScoutPostinst,
}:

# Debian packages for binaries that run directly on bare-metal Ubuntu Noble
# hosts where containers are not an option (e.g. the scout initramfs).
#
# Each deb bundles its full /nix/store closure so the host needs no Nix
# installation. Runtime tools are symlinked under /opt/forge/ so the binary
# finds bundled versions without conflicting with host-installed versions.
#
# Output filenames follow the pattern <name>_<version>_<arch>.deb, which is
# what the setup-apt-repo-{amd64,arm64}-from-nix tasks glob for.
let
  # Arguments shared between the amd64 and arm64 forge-scout debs. The two
  # debs differ only in the binary derivation, runtime tools, and arch field.
  forgeScoutCommon = {
    name = "forge-scout";
    binaryName = "forge-scout";
    installPrefix = "/opt/forge";
    serviceFiles = [ forgeScoutServiceFile ];
    postinst = forgeScoutPostinst;
    description = "Forge scout for performing hardware discovery";
  };

in
{
  # amd64 deb — installed into the scout-oss-x86_64 mkosi initramfs.
  # Bundles tpm2-tools and ipmitool so forge-scout can shell out to them
  # without relying on host-installed versions.
  forge-scout-deb = mkDebPackage (
    forgeScoutCommon
    // {
      package = nativeRustBinaries.carbide-scout;
      arch = "amd64";
      runtime = with pkgs; [
        tpm2-tools
        ipmitool
      ];
    }
  );

  # arm64 deb — installed into the scout-oss-aarch64 mkosi initramfs.
  # Runtime tools (tpm2-tools, ipmitool) come from Ubuntu packages already
  # present in the aarch64 mkosi image rather than being bundled here, since
  # cross-building those C packages from x86_64 is complex.
  # TODO: bundle aarch64 tpm2-tools and ipmitool once cross-build is validated
  # (use pkgs.pkgsCross.aarch64-multiplatform.*).
  forge-scout-deb-arm64 = mkDebPackage (
    forgeScoutCommon
    // {
      package = carbideScoutAarch64;
      arch = "arm64";
    }
  );
}
