{
  pkgs,
  nix2containerLib,
  containerCopyHelpers,
  bombon,
  system,
  # Default image tag — typically the git revision of the workspace.
  version,
  mkOssSources,
}:

# Build an OCI container image from a set of Nix packages.
#
# Two-phase build:
#   Phase 1 — assemble base content (binaries + runtime + OSS sources).
#   Phase 2 — generate a CycloneDX attribution SBOM from the base and bake
#              it into the final image at /usr/share/carbide/attribution.cdx.json.
#
# SBOM generation uses bombon's buildBom called directly on the first element
# of `packages` (the Rust binary carrying bombonVendoredSbom / cargo-cyclonedx
# data), with the remaining packages and runtime deps as extraPaths. This is
# required because nixpkgs' buildEnv excludes `paths` from drvAttrs, so
# bombon's drvDeps traversal cannot reach the binary through a buildEnv wrapper.
#
# The container also includes OSS source tarballs at /usr/share/oss-sources/
# (via mkOssSources) to satisfy the OSRB source-availability requirement.
{
  name,
  packages,
  runtime ? [ ],
  tag ? version,
  arch ? pkgs.go.GOARCH,
  extraContents ? [ ],
  extraCommands ? "",
  meta ? { },
}:
let
  ossSources = mkOssSources name runtime;

  extraCommandsPath = pkgs.lib.optional (extraCommands != "") (
    pkgs.runCommand "${name}-container-extra-root" { } ''
      mkdir -p "$out"
      cd "$out"
      ${extraCommands}
    ''
  );

  pathsToLink = [
    "/bin"
    "/sbin"
    "/etc"
    "/lib"
    "/lib64"
    "/share"
    "/usr"
    "/var"
  ];

  imageConfig = {
    Env = [
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "PATH=/bin:/usr/bin"
    ];
    # No Cmd — the k8s deployment spec (or `docker run …`)
    # picks which carbide binary in the image actually runs.
  };

  basePaths =
    packages
    ++ runtime
    ++ [ pkgs.cacert ossSources ]
    ++ extraContents
    ++ extraCommandsPath;

  # Phase 1: base content without the attribution file.
  preAttributionRoot = pkgs.buildEnv {
    name = "${name}-container-root-pre";
    paths = basePaths;
    inherit pathsToLink;
  };

  preAttributionImage = nix2containerLib.buildImage {
    name = "${name}-pre-attribution";
    inherit tag arch;
    maxLayers = 100;
    copyToRoot = preAttributionRoot;
    config = imageConfig;
  };

  # Phase 2: CycloneDX attribution SBOM.
  # buildBom must target the derivation that carries bombonVendoredSbom —
  # wrapping it in buildEnv or a nix2container image hides it from bombon's
  # drvAttrs traversal. Runtime packages reach the SBOM via extraPaths →
  # closureInfo, which the bombon transformer maps to nixpkgs license metadata.
  attributionSbom = bombon.lib.${system}.buildBom (builtins.head packages) {
    includeBuildtimeDependencies = false;
    extraPaths =
      pkgs.lib.tail packages
      ++ runtime
      ++ [ pkgs.cacert ]
      ++ extraContents
      ++ extraCommandsPath;
  };

  attributionPath = pkgs.runCommand "${name}-attribution-path" { } ''
    mkdir -p $out/usr/share/carbide
    cp ${attributionSbom} $out/usr/share/carbide/attribution.cdx.json
  '';

  # Phase 3: final image with attribution baked in.
  # maxLayers = 100 gives nix2container room to split the closure into
  # fine-grained layers for better registry cache reuse.
  root = pkgs.buildEnv {
    name = "${name}-container-root";
    paths = basePaths ++ [ attributionPath ];
    inherit pathsToLink;
  };

  rawImage = nix2containerLib.buildImage {
    inherit name tag arch;
    maxLayers = 100;
    copyToRoot = root;
    config = imageConfig;
  };

  image = rawImage.overrideAttrs (old: {
    inherit meta;
    passthru =
      builtins.removeAttrs (old.passthru or { }) [
        "copyToDockerDaemon"
        "copyToRegistry"
        "copyToPodman"
        "copyTo"
      ]
      // {
        copyToDockerDaemon = containerCopyHelpers.copyToDockerDaemon rawImage;
        copyToRegistry = containerCopyHelpers.copyToRegistry rawImage;
        copyTo = containerCopyHelpers.copyTo rawImage;
        # Expose packages and runtime so containerSboms can call buildBom
        # with the same drv/extraPaths split used for the attribution file.
        sbomPackages = packages;
        sbomRuntime = runtime;
      };
  });
in
image
