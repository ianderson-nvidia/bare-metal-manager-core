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
# Three-phase build:
#   Phase 1 — assemble base content (binaries + runtime + OSS sources).
#   Phase 2 — generate a CycloneDX attribution SBOM from the assembled base.
#   Phase 3 — bake the SBOM into the final image at
#              /usr/share/carbide/attribution.cdx.json.
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
  # OCI Entrypoint and Cmd. Both are optional; when omitted the image has no
  # default entry point and the k8s PodSpec `command:`/`args:` fields drive
  # execution. Set Entrypoint for containers that run standalone (DPU images,
  # sidecar containers) where the image itself must declare what to run.
  entrypoint ? null,
  cmd ? null,
  # Legacy /opt/carbide/ compatibility for PodSpecs not yet updated to /bin.
  #
  # optCarbideAliases — list of { alias, target } attrsets. Creates a symlink
  # /opt/carbide/<alias> → /bin/<target> for each entry. Use when a binary was
  # renamed and the PodSpec still references the old name.
  #   [ { alias = "forge-admin-cli"; target = "nico-admin-cli"; } ]
  #
  # optCarbideDirs — list of paths to mkdir -p under /opt/carbide/. Use for
  # directories the service expects to exist at startup (mount points, etc.).
  #   [ "pxe/templates" "migrations" "static" ]
  optCarbideAliases ? [ ],
  optCarbideDirs ? [ ],
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

  # Backward-compat layer for /opt/carbide/:
  #   1. Symlink every /bin/* binary so PodSpecs referencing /opt/carbide/<name> work.
  #   2. Create legacy name aliases for renamed binaries.
  #   3. Create directory stubs expected at runtime (mount points, path checks).
  optCarbideCompat = pkgs.runCommand "${name}-opt-carbide-compat" { } ''
    mkdir -p $out/opt/carbide

    ${pkgs.lib.concatMapStrings (pkg: ''
      if [ -d "${pkg}/bin" ]; then
        for bin in "${pkg}"/bin/*; do
          bname=$(basename "$bin")
          ln -sf "/bin/$bname" "$out/opt/carbide/$bname"
        done
      fi
    '') packages}

    ${pkgs.lib.concatMapStrings ({ alias, target }: ''
      ln -sf "/bin/${target}" "$out/opt/carbide/${alias}"
    '') optCarbideAliases}

    ${pkgs.lib.concatMapStrings (dir: ''
      mkdir -p "$out/opt/carbide/${dir}"
    '') optCarbideDirs}
  '';

  pathsToLink = [
    "/bin"
    "/sbin"
    "/etc"
    "/lib"
    "/lib64"
    "/opt"
    "/share"
    "/usr"
    "/var"
  ];

  imageConfig =
    {
      Env = [
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "PATH=/bin:/usr/bin"
      ];
    }
    // pkgs.lib.optionalAttrs (entrypoint != null) { Entrypoint = entrypoint; }
    // pkgs.lib.optionalAttrs (cmd != null) { Cmd = cmd; };

  basePaths =
    packages
    ++ runtime
    ++ [ pkgs.cacert ossSources optCarbideCompat ]
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
