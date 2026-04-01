{
  craneLib,
  commonArgs,
  cargoArtifacts,
  allBuildInputs,
}:

# Default helper for native workspace binaries. The deps phase is shared via
# `cargoArtifacts`, so each package derivation only rebuilds workspace crates.
{
  pname,
  cargoExtraArgs ? "",
  meta ? { },
  extraArgs ? { },
}:
let
  extraBuildInputs = extraArgs.buildInputs or [ ];
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit pname cargoArtifacts meta;
    cargoExtraArgs = "--package ${pname} ${cargoExtraArgs}";
    doInstallCargoArtifacts = false;
    buildInputs = allBuildInputs ++ extraBuildInputs;
  }
  // builtins.removeAttrs extraArgs [ "buildInputs" ]
)
