{
  pkgs,
  crane,
  rustToolchainFor,
  src,
  version,
  crossPkgs ? pkgs.pkgsCross.aarch64-multiplatform // {
    stdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
  },
}:

let
  # Initialize crane against the aarch64 package set. Passing a toolchain
  # function lets crane splice the Rust toolchain through the build/host/target
  # package sets correctly for cross compilation.
  crossCraneLib = (crane.mkLib crossPkgs).overrideToolchain rustToolchainFor;
in
# Cross-compile a single workspace binary for aarch64. We intentionally do not
# pass native cargoArtifacts: x86_64 deps cannot be reused for an aarch64 link.
# `buildPackage` derives target-specific deps from these same cross args.
{
  pname,
  cargoExtraArgs ? "",
  extraArgs ? { },
}:
let
  extraBuildInputs = extraArgs.buildInputs or [ ];
in
crossCraneLib.buildPackage (
  {
    inherit src version pname;
    strictDeps = true;
    doCheck = false;
    doInstallCargoArtifacts = false;

    cargoExtraArgs = "--package ${pname} ${cargoExtraArgs}";

    CARGO_BUILD_TARGET = "aarch64-unknown-linux-gnu";
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";

    # Build scripts compile for and run on the build host, even while the final
    # binary targets aarch64.
    depsBuildBuild = with pkgs; [
      stdenv.cc
    ];

    # Target libraries come from pkgsCross because the final binary links against
    # aarch64 system libraries.
    buildInputs =
      (with crossPkgs; [
        openssl
        tpm2-tss.dev
        libudev-zero
      ])
      ++ extraBuildInputs;

    # Add aarch64 libgcc to the runtime RPATH without leaking it into host
    # build-script link paths.
    runtimeDependencies = [
      crossPkgs.stdenv.cc.cc.lib
    ];
    autoPatchelfIgnoreMissingDeps = [ "libgcc_s.so.1" ];

    # Native build tools run on the host, not the target.
    nativeBuildInputs = with pkgs; [
      cmake
      clang
      lld
      pkg-config
      protobuf
      autoPatchelfHook
    ];

    SQLX_OFFLINE = "true";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
  }
  // builtins.removeAttrs extraArgs [ "buildInputs" ]
)
