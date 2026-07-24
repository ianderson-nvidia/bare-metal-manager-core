{
  pkgs,
  # Default image tag — typically the git revision of the workspace.
  version,
}:

# Build a self-contained Debian package from a Nix derivation.
#
# The full /nix/store closure of the binary (and any runtime tools) is bundled
# inside the deb payload. On install, dpkg places those store paths on the host
# at /nix/store/, so the binary's autoPatchelfHook RPATHs resolve correctly
# with no Nix installation required on the target.
#
# Runtime tools (tpm2-tools, ipmitool, etc.) are exposed as symlinks under
# installPrefix so the binary can find them without conflicting with any
# host-installed versions. A wrapper script placed at installPrefix/<binaryName>
# sets PATH to installPrefix before exec-ing the real binary, so shell-outs
# to bundled tools work without modifying the service file.
#
# Typical call:
#
#   mkDebPackage {
#     name        = "scout";
#     package     = nativeRustBinaries.carbide-scout;
#     binaryName  = "forge-scout";
#     runtime     = with pkgs; [ tpm2-tools ipmitool ];
#     serviceFiles = [ ./crates/scout/misc/forge-scout.service ];
#     postinst    = ./crates/scout/misc/DEBIAN/postinst;
#     arch        = "amd64";
#     description = "Forge scout for performing hardware discovery";
#   }
{
  # deb Package: field (e.g. "scout" → forge-scout_<ver>_amd64.deb).
  name,

  # Main Nix derivation — the binary to bundle.
  package,

  # Binary filename inside package/bin/. Defaults to meta.mainProgram if set.
  binaryName ? package.meta.mainProgram or name,

  # Path on the installed system where the wrapper and runtime symlinks live.
  # The existing service file references /opt/forge/, so this must match.
  installPrefix ? "/opt/forge",

  # Extra Nix packages whose bin/* are symlinked into installPrefix.
  # These are included in the closure and exposed alongside the main binary
  # so the binary can shell out to them without touching host-installed versions.
  runtime ? [ ],

  # .service files installed under /lib/systemd/system/.
  serviceFiles ? [ ],

  # Optional DEBIAN/postinst script path. Receives standard dpkg postinst args.
  postinst ? null,

  # deb Architecture: field — "amd64" or "arm64".
  arch ? "amd64",

  # Output filename for the .deb file. Defaults to <name>_<version>_<arch>.deb.
  # Override when the consuming build system expects a specific name
  # (e.g. mkosi.postinst.chroot uses `dpkg -i /build-output/forge-scout.deb`).
  fileName ? "${name}_${version}_${arch}.deb",

  description ? "",
  section ? "base",
  maintainer ? "Forge team <swngc-forge-dev@nvidia.com>",
}:
let
  # Debian policy requires Version to start with a digit. Git short revs
  # (e.g. "fe153c8-dirty") do not. Prefix them with "0~" so dpkg accepts
  # them; "~" sorts below any real release, which is correct for dev builds.
  debVersion =
    if builtins.match "[0-9].*" version != null then version else "0~${version}";

  allPkgs = [ package ] ++ runtime;

  # closureInfo produces a text file listing every transitive /nix/store path
  # that the binary and runtime tools depend on.
  closure = pkgs.closureInfo { rootPaths = allPkgs; };

  # Wrapper script placed at installPrefix/<binaryName>.
  # Prepends installPrefix to PATH so any runtime tool symlinks there
  # (tpm2_getcap, ipmitool, etc.) are found before host-installed versions,
  # then execs the real binary at its fixed nix store path.
  wrapperScript = pkgs.writeShellScript "${binaryName}-wrapper" ''
    export PATH="${installPrefix}:$PATH"
    exec ${package}/bin/${binaryName} "$@"
  '';

  # preinst creates /nix/store/ on the target before dpkg unpacks the payload.
  # Targets that have never had a nix-based deb installed won't have /nix at all.
  # Must use #!/bin/sh — pkgs.writeShellScript would embed a Nix-store bash path
  # that doesn't exist yet when preinst runs (the store is what we're creating).
  preinst = pkgs.writeText "${name}-preinst" ''
    #!/bin/sh
    set -e
    mkdir -p /nix/store
    chmod 755 /nix
    chmod 1775 /nix/store
  '';

  # Generate the control file as a Nix derivation to avoid heredoc indentation
  # issues inside the build script.
  controlFile = pkgs.writeText "${name}-control" ''
    Package: ${name}
    Version: ${debVersion}
    Section: ${section}
    Priority: optional
    Architecture: ${arch}
    Maintainer: ${maintainer}
    Description: ${description}
  '';

in
pkgs.runCommand "${fileName}" {
  nativeBuildInputs = [ pkgs.dpkg ];
} ''
  staging=$TMPDIR/staging
  mkdir -p $staging

  # ------------------------------------------------------------------
  # 1. Bundle the full nix store closure.
  #    Every store path the binary and runtime tools transitively depend
  #    on is copied so the deb is completely self-contained.
  # ------------------------------------------------------------------
  mkdir -p $staging/nix/store
  while IFS= read -r storePath; do
    cp -a "$storePath" "$staging/nix/store/"
  done < ${closure}/store-paths

  # ------------------------------------------------------------------
  # 2. Wrapper script and runtime tool symlinks under installPrefix.
  # ------------------------------------------------------------------
  mkdir -p "$staging${installPrefix}"

  # The wrapper sets PATH and execs the real binary from its store path.
  # The service file's ExecStart references this path directly.
  cp ${wrapperScript} "$staging${installPrefix}/${binaryName}"
  chmod 0755 "$staging${installPrefix}/${binaryName}"

  # Symlink each runtime tool binary into installPrefix so the binary
  # finds bundled versions rather than (potentially absent) host versions.
  ${pkgs.lib.concatMapStrings (p: ''
    for bin in ${p}/bin/*; do
      bname=$(basename "$bin")
      ln -sf "$bin" "$staging${installPrefix}/$bname"
    done
  '') runtime}

  # ------------------------------------------------------------------
  # 3. Systemd service files.
  # ------------------------------------------------------------------
  ${pkgs.lib.optionalString (serviceFiles != [ ]) ''
    mkdir -p "$staging/lib/systemd/system"
    ${pkgs.lib.concatMapStrings (svc: ''
      cp ${svc} "$staging/lib/systemd/system/$(basename ${toString svc})"
    '') serviceFiles}
  ''}

  # ------------------------------------------------------------------
  # 4. DEBIAN metadata.
  # ------------------------------------------------------------------
  mkdir -p $staging/DEBIAN

  cp ${preinst} $staging/DEBIAN/preinst
  chmod 0755 $staging/DEBIAN/preinst

  ${pkgs.lib.optionalString (postinst != null) ''
    cp ${postinst} $staging/DEBIAN/postinst
    chmod 0755 $staging/DEBIAN/postinst
  ''}

  cp ${controlFile} $staging/DEBIAN/control

  # ------------------------------------------------------------------
  # 5. Build the deb.
  # ------------------------------------------------------------------
  mkdir -p $out
  dpkg-deb --build $staging "$out/${fileName}"
''
