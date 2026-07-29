# `nix run .#sbom-<name>` — generate SBOMs for a container image.
#
# sbomnix walks the image's Nix store closure rather than probing a running
# filesystem, so the result covers every runtime dependency exactly as Nix
# resolved it — no package-manager database to consult and nothing inferred
# from file layout.
#
# Three formats are emitted from the single traversal because their consumers
# differ: nSpect ingests CycloneDX, most other scanners prefer SPDX, and the
# CSV is what a human reads when reconciling an SBOM against a review.
#
# Outputs land in the current working directory, not the Nix store, since the
# point is to hand the files to something outside Nix. They are gitignored.
{
  pkgs,
  # amd64 container derivations, keyed by image name.
  containers,
}:

let
  mkSbomScript =
    name: container:
    pkgs.writeShellApplication {
      name = "sbom-${name}";
      runtimeInputs = [ pkgs.sbomnix ];
      text = ''
        echo "Generating SBOM for ${name}..."
        sbomnix \
          --cdx  "./${name}.cdx.json" \
          --spdx "./${name}.spdx.json" \
          --csv  "./${name}.csv" \
          ${container}
        echo "SBOMs written to:"
        echo "  ./${name}.cdx.json   (CycloneDX — nSpect, grype)"
        echo "  ./${name}.spdx.json  (SPDX — broader toolchain)"
        echo "  ./${name}.csv        (human-readable summary)"
      '';
    };
in

pkgs.lib.mapAttrs' (
  name: container:
  pkgs.lib.nameValuePair "sbom-${name}" {
    type = "app";
    program = "${mkSbomScript name container}/bin/sbom-${name}";
  }
) containers
