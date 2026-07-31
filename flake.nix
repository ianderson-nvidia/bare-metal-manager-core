/*
  BUILDING TARGETS
  ================

  List every available build target:

    nix flake show

  Build a specific target (output lands in ./result):

    nix build .#<name>

  Common examples:

    nix build .#carbide-api                    # native x86_64 binary
    nix build .#carbide-api-container          # x86_64 OCI container image
    nix build .#carbide-api-container-arm64    # arm64 OCI container image
    nix build .#carbide-dhcp                   # Kea hook library (libdhcp.so)
    nix build .#carbide-dhcp-container         # x86_64 DHCP container
    nix build .#forge-scout-deb                # .deb package (x86_64)
    nix build .#ipxe-efi-x86                   # iPXE EFI bootloader

  List every runnable target (`nix run`), defined under nix/apps/:

    nix flake show

  Load a container into the local Docker daemon:

    nix run .#carbide-api-container-copy-to-docker

  Generate a CycloneDX SBOM for a container (for nSpect upload):

    nix run .#sbom-carbide-api-container

  Enter the dev shell (Rust toolchain + all build tools):

    nix develop

  WHERE TO MAKE CHANGES

    nix/services/default.nix   what goes into a service's container image —
                               runtime tools, entrypoint, directory fixups
    nix/container/             the container builder, and images assembled
                               from staged files rather than a binary
    nix/rust/, nix/go/         how binaries are compiled
    nix/deb/, nix/boot/        .deb packages and iPXE bootloaders
    nix/apps/                  `nix run` targets

  Nix language quick reference
  Full docs: https://nix.dev/tutorials/nix-language
             https://nix.dev/manual/nix/2.26/language/
  nixpkgs lib search: https://noogle.dev

  KEY PROPERTIES
  ==============

  1. Everything is an expression — there are no statements. `if`, `let`, and
     `with` all produce values. In imperative languages `if` executes code; in
     Nix it evaluates to whichever branch was taken:

     buildInputs = if pkgs.stdenv.isLinux then [ pkgs.libudev ] else [];

     `let` evaluates to whatever follows `in`:

     let
       x = 5;
       label = if x > 3 then "big" else "small";
     in
     label  # -> "big"

  2. Immutable — bindings cannot be changed after they are set. `//` does not
     mutate an attrset; it produces a new one with the right-hand side winning
     on duplicate keys:

     { a = 1; b = 2; } // { b = 99; }  # -> { a = 1; b = 99; }

  3. Lazy — expressions are only evaluated when their value is needed.
     Evaluating a flake (e.g. `nix flake show`) does not build anything; a
     derivation is only realised when you explicitly request it (`nix build`).
     This is why a flake with hundreds of packages doesn't try to build them
     all up front.

  4. Functional — functions are first-class values. `rustToolchainFor` below is
     a plain binding that happens to hold a function.

  TYPES
  =====
  string, integer, boolean, null, list, attrset, path, function, derivation.
  There is no type system; type errors surface at evaluation time.

  FUNCTIONS
  =========
  Functions are defined with a colon — `argument: body`:

    x: x + 1          # anonymous function
    (x: x + 1) 5      # -> 6

  Bind a name in a `let`:

    let addOne = x: x + 1;
    in addOne 5        # -> 6

  Multiple arguments use currying — each `:` adds one parameter:

    let add = x: y: x + y;
    in add 3 4         # -> 7

  Attrset destructuring (the dominant pattern in nixpkgs and flakes):

    let
      say = { name, statement }: "${name}. ${statement}!";
    in
    say { name = "Joseph Miller"; statement = "it reaches out"; }

  `{ pkgs, system, version, ... }: ...` is a function that destructures named
  fields from an attrset. `...` means "accept extra fields I haven't named".

  COMMON SYNTAX
  =============

  inherit — shorthand for copying a binding by name:
    inherit pkgs;            # same as: pkgs = pkgs;
    inherit (foo) a b;       # same as: a = foo.a; b = foo.b;

  with — bring all attributes of a set into scope for one expression:
    with pkgs; [ curl openssl tpm2-tools ]
    # equivalent to: [ pkgs.curl pkgs.openssl pkgs.tpm2-tools ]

  import — evaluate a .nix file, optionally calling it as a function:
    import ./nix/go/rest-api.nix { inherit pkgs version; }
    # Reads the file, which returns a function, then calls it with the attrset.

  Paths vs strings — path literals (no quotes) are copied into the Nix store
  and resolve relative to the file they appear in:
    src = ./rest-api;      # path — added to the store, works as a source
    src = "./rest-api";    # string — NOT a path; will fail as a derivation src

  String interpolation uses ${ }:
    "--prefix=${pkgs.openssl}/lib"

  FLAKE STRUCTURE
  ===============
  A flake is an attrset with `description`, `inputs`, and `outputs`. The
  `outputs` attribute is a function that receives the resolved inputs and
  returns the flake's public attrset (packages, devShells, apps, etc.).
  The body of `outputs` is one large `let ... in` block — all the derivations
  and helper functions in this file live in that `let`.
*/


{
  description = "Infra Manager (Carbide) — Nix build infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # crane: two-phase Rust build caching (deps separate from source).
    crane.url = "github:ipetkov/crane";

    # flake-utils: helpers for multi-system outputs (x86_64, aarch64).
    flake-utils.url = "github:numtide/flake-utils";

    # nix2container: OCI-native image metadata with direct copy helpers.
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # rust-overlay: provides exact Rust toolchain versions.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      nix2container,
      rust-overlay,
    }:
    # eachSystem iterates over an explicit list of systems, evaluating the
    # function for each, and merges the results into the flake outputs attrset.
    # https://github.com/numtide/flake-utils
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (
      system:
      let
        # Instantiate nixpkgs for this system. `import nixpkgs { system; }` is
        # how you get a package set bound to a specific platform — every
        # derivation in `pkgs` will be built for and run on `system`.
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          # overlays are a list of functions that patch or extend a package set.
          overlays = [
            rust-overlay.overlays.default
          ];
        };

        isLinux = pkgs.stdenv.isLinux;

        # Crane wants a function over the package set `p` rather than a pre-built
        # derivation so it can splice the toolchain through build/host/target
        # package sets correctly when cross-compiling.
        # https://github.com/oxalica/rust-overlay
        # Read the channel from rust-toolchain.toml rather than hardcoding it.
        # cargo-make, the Dockerfiles, and rustup all honour that file, so
        # duplicating the version here lets the flake silently drift onto a
        # different rustc than the one that produces the shipping binaries —
        # which it had (flake 1.95.0 vs rust-toolchain.toml 1.96.0).
        rustChannel = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;

        # Nightly is needed only for rustfmt: rustfmt.toml sets
        # unstable_features plus imports_granularity / group_imports /
        # format_code_in_doc_comments / normalize_doc_attributes, none of which
        # stable rustfmt accepts. Keep in sync with RUST_NIGHTLY in Makefile.toml.
        rustNightlyDate = "2026-06-16";

        # Components mirror what setup-nightly-rust installs via rustup:
        # rustfmt for the format checks, and rust-src/rustc-dev/llvm-tools for
        # carbide-lints, which is a rustc driver and links against rustc
        # internals. Supplying this from Nix means the lint tasks work under
        # `nix develop` without rustup — the Nix cargo rejects `+toolchain`.
        rustNightlyToolchain = pkgs.rust-bin.nightly.${rustNightlyDate}.default.override {
          extensions = [
            "rustfmt"
            "rust-src"
            "rustc-dev"
            "llvm-tools-preview"
          ];
        };

        rustToolchainFor =
          p:
          p.rust-bin.stable.${rustChannel}.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "aarch64-unknown-linux-gnu"
            ];
          };

        # Initialize crane with the custom Rust toolchain above. All craneLib.*
        # calls in this file use this instance.
        # https://crane.dev/API.html#cranemklib
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchainFor;

        # nix2container library — provides buildImage and the OCI layer-diffing
        # machinery used by mkContainer.
        # https://github.com/nlewo/nix2container
        nix2containerLib = nix2container.packages.${system}.nix2container;

        # Skopeo-based copy helpers: copyToDockerDaemon, copyToRegistry,
        # copyToRegistryMultiArch. Uses a patched skopeo with nix: transport
        # so images can be copied directly from the Nix store.
        containerCopyHelpers = import ./nix/container/nix2container-skopeo.nix {
          inherit pkgs;
          skopeoNix2container = nix2container.packages.${system}.skopeo-nix2container;
        };

        # ====================================================================
        # System dependencies
        # ====================================================================
        nativeBuildInputs =
          (with pkgs; [
            cmake
            clang
            pkg-config
            protobuf
          ])
          ++ pkgs.lib.optionals isLinux (with pkgs; [
            # lld and autoPatchelfHook are Linux-only: macOS uses ld64 and
            # does not have ELF RPATH patching.
            lld
            # autoPatchelfHook embeds Nix-store paths in RPATH so the binary
            # finds its .so deps without LD_LIBRARY_PATH. Production
            # deployment ships the binaries inside containers via
            # mkContainer, which bundles the full /nix/store closure;
            # /nix/store paths exist inside the image so RPATH resolves
            # cleanly.
            autoPatchelfHook
          ]);

        # Union of every C library any crate in the workspace might link.
        #
        # The deps phase (cargoArtifacts) needs this complete set: cargo
        # compiles every external crate including -sys crates whose build.rs
        # calls pkg-config for "their" library. Missing any one library
        # fails the deps phase even if no individual binary needs it.
        #
        # Version assertion: libudev-zero is a drop-in libudev replacement
        # linked into every Rust binary. A version bump warrants a sanity
        # check before accepting. Update the string below after verifying.
        allBuildInputs =
          assert pkgs.libudev-zero.version == "1.0.3"
            || builtins.throw ''
                libudev-zero version changed to ${pkgs.libudev-zero.version}.
                Verify ABI compatibility, then update the assertion in flake.nix.
              '';
          (with pkgs; [
            libudev-zero
          ])
          ++ pkgs.lib.optionals isLinux [
            pkgs.tpm2-tss.dev
            # Rust binaries implicitly depend on libgcc_s.so.1.
            # Putting it in buildInputs makes autoPatchelfHook find it and write
            # the correct /nix/store RPATH entry.
            pkgs.stdenv.cc.cc.lib
          ];

        # ====================================================================
        # Source filtering
        # ====================================================================

        # Declare sources additively using filesets. We start with crane's
        # defaults (Cargo.{toml,lock}, .rs files, rust-toolchain.toml) and add
        # extra non-Rust files referenced at build or test time. Being explicit
        # about what's included means changes outside these paths (helm charts,
        # READMEs, etc.) don't invalidate the Nix build cache.
        # The deps cache (cargoArtifacts) uses the narrower `depsSrc` below,
        # so .rs-only changes don't force an external-crate rebuild.

        # https://noogle.dev/f/lib/fileset/toSource/
        src = pkgs.lib.fileset.toSource {
          root = ./.; 
          # https://noogle.dev/f/lib/fileset/unions/
          fileset = pkgs.lib.fileset.unions [
            # Deliberately not craneLib.fileset.commonCargoSources: that is
            # cargoTomlAndLock ∪ rust ∪ toml, and its `toml` component matches
            # *every* .toml in the tree. At the repo root that pulls in
            # Makefile.toml, clippy.toml, deny.toml, Cross.toml and .taplo.toml
            # — none of which cargo reads during a build, but all of which would
            # then invalidate every binary and container on a cargo-make edit.
            # https://crane.dev/API.html#cranelibfilesetcargotomlandlock
            (craneLib.fileset.cargoTomlAndLock ./.)
            # https://crane.dev/API.html#cranelibfilesetrust
            (craneLib.fileset.rust ./.)
            ./crates
            # Non-Rust files outside crates/ referenced at build/test time.
            ./.cargo
            # PXE boot templates referenced by crates via
            # include_str!("").
            ./pxe/templates
            ./pxe/ipxe/local
            # bmc-mock embeds the ipmi_sim fixtures with include_bytes!, and it
            # is a regular dependency of machine-a-tron rather than a dev-only
            # one, so these are needed for a release build and not just tests.
            ./dev/ipmi
          ];
        };

        # Derive version from git. `self` refers to the flake itself
        version = self.shortRev or self.dirtyShortRev or "dev";

        # ====================================================================
        # Common arguments shared by all crane derivations.
        # ====================================================================
        commonArgs = {
          inherit
            src
            version
            nativeBuildInputs
            ;

          # Note: no buildInputs here. The deps phase and mkCrateBinary inject
          # `allBuildInputs` explicitly; individual binaries can append extra
          # inputs via extraArgs without affecting the shared dep-phase cache.
          pname = "carbide-workspace";
          strictDeps = true;
          doCheck = false;

          # Workspace-wide env vars.
          # The Nix sandbox has no network and no database. SQLX_OFFLINE tells
          # sqlx to use the pre-generated .sqlx/ query metadata checked into the
          # repo rather than connecting to a live Postgres instance at compile time.
          # Run `cargo sqlx prepare` against a real DB to regenerate .sqlx/ after
          # query changes, then commit the result.
          SQLX_OFFLINE = "true";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          # clang is already in nativeBuildInputs as the C compiler for -sys crates;
          # using it as the linker driver lets Cargo find lld (also in
          # nativeBuildInputs) without any additional path wiring.
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "clang";

        };

        # ====================================================================
        # Phase 1: Build only workspace dependencies.
        #
        # This derivation compiles every external crate dependency but none
        # of the carbide source. Input hash depends only on Cargo.lock and
        # Cargo.toml files, so source-only changes get a cache hit here.
        # ====================================================================

        # https://crane.dev/API.html?highlight=cleanCargoSource#cranelibcleancargosource
        depsSrc = craneLib.cleanCargoSource ./.;

        # buildDepsOnly → mkCargoDerivation → stdenv.mkDerivation. Functions
        # that wrap mkDerivation accept `...` and forward unknown arguments
        # straight through, which is why passing `buildInputs` here works even
        # though buildDepsOnly doesn't explicitly declare that parameter.
        # https://crane.dev/API.html#cranelibbuilddepsonly
        # https://nixos.org/manual/nixpkgs/stable/#var-stdenv-buildInputs
        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            src = depsSrc;

            # Deps phase compiles every external -sys crate; needs the full
            # library union so each one's build.rs finds its C library via
            # pkg-config.
            buildInputs = allBuildInputs;
          }
        );


        # Builds one native workspace binary, reusing the pre-compiled external
        # crate cache from cargoArtifacts. See nix/rust/crate-binary.nix.
        mkCrateBinary = import ./nix/rust/crate-binary.nix {
          inherit
            craneLib
            commonArgs
            cargoArtifacts
            allBuildInputs
            ;
        };

        mkCrateHookLib = import ./nix/rust/crate-hook-lib.nix {
          inherit
            craneLib
            commonArgs
            cargoArtifacts
            allBuildInputs
            ;
        };

        # ====================================================================
        # Cross-compile pipeline for aarch64 binaries.
        #
        # Used for binaries that ship to aarch64 systems (carbide-scout,
        # carbide-agent, forge-dhcp-server, etc.). The helper intentionally
        # does not reuse native cargoArtifacts because x86_64 deps cannot be
        # reused for an aarch64 link; crane derives target-specific deps from
        # each cross package's args.
        # ====================================================================
        # pkgsCross.aarch64-multiplatform is a nixpkgs package set where every
        # derivation is built for aarch64-linux using a cross-compiler running
        # on the host. Overriding stdenv to gcc13Stdenv matches Ubuntu 24.04's
        # default toolchain and avoids ABI inconsistencies with the iPXE EFI
        # binary (also built with gcc 13 via ipxe-x86.nix).
        aarch64CrossPkgs = pkgs.pkgsCross.aarch64-multiplatform // {
          stdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
        };

        mkCrossCrateBinary = import ./nix/rust/cross-crate-binary-aarch64.nix {
          inherit
            pkgs
            crane
            rustToolchainFor
            src
            version
            ;
          crossPkgs = aarch64CrossPkgs;
        };

        mkCrossHookLib = import ./nix/rust/cross-crate-hook-lib-aarch64.nix {
          inherit
            pkgs
            crane
            rustToolchainFor
            src
            version
            ;
          crossPkgs = aarch64CrossPkgs;
        };

        # libkea ships its C++ library as libkea-dhcp.so.* (versioned), but
        # crates/dhcp/build.rs emits `cargo:rustc-link-lib=kea-dhcp++`, so the
        # linker looks for libkea-dhcp++.so — a name Kea does not provide.
        # This shim is a lib dir carrying that alias.
        #
        # Both the package builds and the dev shell point KEA_LIB_PATH here.
        # They used to diverge (the builds did this inline in postConfigure, the
        # dev shell pointed straight at ${kea}/lib), which meant carbide-dhcp
        # could not be built inside `nix develop` at all.
        mkKeaLibShim =
          p:
          pkgs.runCommand "kea-lib-shim-${p.kea.version}" { } ''
            mkdir -p $out/lib
            ln -sf ${p.kea}/lib/libkea-*.so* $out/lib/
            ln -sf ${p.kea}/lib/libkea-dhcp.so $out/lib/libkea-dhcp++.so
          '';

        #
        # Version assertion: libdhcp.so links against libkea-*.so with
        # ABI-versioned SONAMEs. A Kea major version bump changes those SONAMEs,
        # breaking hook loading at runtime with an opaque dlopen error. Update
        # the string below after verifying hook ABI compatibility.
        dhcpCrateExtraArgs = dhcpPkgs:
          assert dhcpPkgs.kea.version == "3.0.3"
            || builtins.throw ''
                kea version changed to ${dhcpPkgs.kea.version}.
                libdhcp.so links against libkea-*.so — verify hook ABI compatibility
                before accepting. Then update the assertion in flake.nix.
              '';
          {
          buildInputs = with dhcpPkgs; [
            stdenv.cc.cc.lib
            kea
            boost.dev
          ];
          KEA_INCLUDE_PATH = "${dhcpPkgs.kea}/include/kea";
          KEA_LIB_PATH = "${mkKeaLibShim dhcpPkgs}/lib";
        };

        # Shared metadata applied to every carbide workspace binary.
        # sbomnix reads meta.license and meta.homepage to populate
        # the licenseDeclared / downloadLocation fields in generated SBOMs.
        carbideMeta = {
          license = pkgs.lib.licenses.asl20;
          homepage = "https://github.com/NVIDIA/infra-controller";
          maintainers = [ ];
        };

        # ====================================================================
        # Per-architecture binary sets
        #
        # The cargo PACKAGE names are carbide-* but each crate's [[bin]] target
        # may rename the BINARY to forge-* — so we build by package name and
        # downstream consumers see the forge-* binary in $out/bin/.
        # ====================================================================

        nativeRustBinaries = {
          carbide-api = mkCrateBinary { pname = "carbide-api"; meta = carbideMeta; };
          carbide-dns = mkCrateBinary { pname = "carbide-dns"; meta = carbideMeta; };
          carbide-pxe = mkCrateBinary { pname = "carbide-pxe"; meta = carbideMeta; };
          carbide-dhcp = mkCrateHookLib {
            pname = "carbide-dhcp";
            libFileName = "libdhcp.so";
            installPath = "usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so";
            meta = carbideMeta;
            extraArgs = dhcpCrateExtraArgs pkgs;
          };
          carbide-dsx-exchange-consumer = mkCrateBinary { pname = "carbide-dsx-exchange-consumer"; meta = carbideMeta; };
          nico-admin-cli = mkCrateBinary { pname = "nico-admin-cli"; meta = carbideMeta; };
          carbide-health = mkCrateBinary { pname = "carbide-health"; meta = carbideMeta; };
          carbide-ssh-console = mkCrateBinary { pname = "carbide-ssh-console"; meta = carbideMeta; };
          # carbide-scout produces a binary named "forge-scout" (per the crate's
          # [[bin]] target); downstream packaging wraps it as needed.
          carbide-scout = mkCrateBinary { pname = "carbide-scout"; meta = carbideMeta; };
          carbide-log-parser = mkCrateBinary { pname = "carbide-log-parser"; meta = carbideMeta; };
          carbide-bmc-proxy = mkCrateBinary { pname = "carbide-bmc-proxy"; meta = carbideMeta; };
          # Hardware simulation tool. x86_64 only — the Dockerfile it replaces
          # hardcoded --target x86_64-unknown-linux-gnu and a linux/amd64 runtime
          # stage, so there is deliberately no aarch64ServerBinaries entry.
          machine-a-tron = mkCrateBinary { pname = "carbide-machine-a-tron"; meta = carbideMeta; };
        };

        # DPU-side binaries. Build host can be either x86_64 or aarch64 —
        # pkgsCross.aarch64-multiplatform resolves to a real cross gcc on x86
        # hosts and to the native aarch64 gcc on aarch64 hosts.
        aarch64Binaries = {
          carbide-dpf = mkCrossCrateBinary {
            pname = "carbide-dpf";
            cargoExtraArgs = "--features driver --bin carbide-dpf-api-harness";
          };
          forge-dpu-agent = mkCrossCrateBinary { pname = "carbide-agent"; meta = carbideMeta; };
          forge-dhcp-server = mkCrossCrateBinary { pname = "carbide-dhcp-server"; meta = carbideMeta; };
          carbide-fmds = mkCrossCrateBinary { pname = "carbide-fmds"; meta = carbideMeta; };
        };

        # Server-side binaries cross-compiled for aarch64. Used alongside
        # aarch64Binaries to build arm64 service containers from an x86_64 host.
        aarch64ServerBinaries =
          let
            mk = pname: mkCrossCrateBinary { inherit pname; };
          in
          {
            carbide-api = mk "carbide-api";
            carbide-dns = mk "carbide-dns";
            carbide-pxe = mk "carbide-pxe";
            carbide-dhcp = mkCrossHookLib {
              pname = "carbide-dhcp";
              libFileName = "libdhcp.so";
              installPath = "usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp.so";
              extraArgs = dhcpCrateExtraArgs aarch64CrossPkgs;
            };
            carbide-dsx-exchange-consumer = mk "carbide-dsx-exchange-consumer";
            nico-admin-cli = mk "nico-admin-cli";
            carbide-health = mk "carbide-health";
            carbide-ssh-console = mk "carbide-ssh-console";
            carbide-scout = mk "carbide-scout";
          };

        # ====================================================================
        # Go binaries (rest-api workspace)
        # ====================================================================

        # Vendor hash for the rest-api Go module. Update via TOFU when go.mod changes:
        #   1. Set to `pkgs.lib.fakeHash`.
        #   2. Run `nix build .#rest-api-api` — the build fails at vendoring
        #      with a "hash mismatch" error printing the expected sha256.
        #   3. Copy that sha256 here and rebuild.
        # All rest-api binaries share this — they all live under the same
        # go.mod, so vendoring is identical for each.
        restApiVendorHash = "sha256-Ty2FyzJeTRpDjBiYuUQ91EPHtKLmzgAg3s9M1UBpOtI=";

        restApi = import ./nix/go/rest-api.nix {
          inherit pkgs version system;
          src = ./rest-api;
          vendorHash = restApiVendorHash;
        };
        restApiBinariesFor = restApi.binariesFor;
        restApiBinariesNative = restApi.binariesNative;
        restApiBinariesAmd64 = restApi.binariesAmd64;
        restApiBinariesArm64 = restApi.binariesArm64;

        # CLI tools exposed by `nix develop`. Container runtime tools are
        # declared per service in nix/services/default.nix so each image only
        # carries the shell-out utilities it actually needs.
        runtimeTools = with pkgs; [
          curl
          ipmitool
          iproute2
          iputils # ping, traceroute, arping
          kea # kea-dhcp4-server + kea-ctrl-agent
          openipmi
          postgresql_15 # psql, pg_dump, etc.
          tpm2-tools
        ];

        # ====================================================================
        # Container builder — see nix/container/make-container.nix for the
        # two-phase build, SBOM strategy, and parameter documentation.
        # ====================================================================

        mkOssSources = import ./nix/container/oss-sources.nix { inherit pkgs; };

        mkContainer = import ./nix/container/make-container.nix {
          inherit
            pkgs
            nix2containerLib
            containerCopyHelpers
            version
            mkOssSources
            ;
        };

        # Build a self-contained Debian package from a Nix derivation.
        # Bundles the full /nix/store closure inside the deb so the binary
        # runs on bare-metal Ubuntu Noble hosts without a Nix installation.
        # See nix/deb/make-deb.nix for full documentation.
        mkDebPackage = import ./nix/deb/make-deb.nix { inherit pkgs version; };

        # Pre-built third-party aarch64 binaries — fetched as fixed-output
        # derivations so Nix can verify them without network access at build time.
        mftAarch64 = import ./nix/third-party/mft-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        transceiverExporterAarch64 = import ./nix/third-party/transceiver-exporter-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        otelcolContribAarch64 = import ./nix/container/otelcol-contrib-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        # Static file trees for the machine-validation images. Arch-independent,
        # so the same derivations feed both the amd64 and arm64 containers.
        machineValidationFiles = import ./nix/container/machine-validation.nix {
          inherit pkgs;
          configDir = ./crates/machine-validation/config;
          imagesDir = ./crates/machine-validation/images;
          scriptsDir = ./crates/machine-validation/scripts;
        };

        # Scripts and firmware bundled into the nsm container at the paths the
        # Dockerfile establishes (WORKDIR /opt/nvswitch-manager before COPY).
        nsmStaticFiles = pkgs.runCommand "rest-api-nsm-static" { } ''
          mkdir -p $out/opt/nvswitch-manager
          cp -r ${./rest-api/nvswitch-manager/scripts}  $out/opt/nvswitch-manager/scripts
          cp -r ${./rest-api/nvswitch-manager/firmware} $out/opt/nvswitch-manager/firmware
        '';

        # What each service's image needs beyond its binary — runtime tools,
        # entrypoint, directory fixups. One entry per service; see
        # nix/services/default.nix for the field reference.
        serviceSpecs = import ./nix/services {
          inherit mftAarch64 otelcolContribAarch64 nsmStaticFiles;
        };

        # Per-service containers — one image per binary per architecture.
        #
        # amd64 containers use nativeRustBinaries and native pkgs runtime tools.
        # arm64 containers use aarch64ServerBinaries / aarch64Binaries (cross-
        # compiled) and aarch64CrossPkgs runtime tools.
        #
        # Each container bakes in:
        #   /usr/share/oss-sources/      OSS source tarballs (OSRB compliance)
        #   /usr/share/carbide/attributions.txt  license notices (OSRB compliance)
        #
        # For nSpect SBOM generation run: nix run .#sbom-<name>-container
        #
        # Exposed at:
        #   nix build .#carbide-api-container          # amd64
        #   nix build .#carbide-api-container-arm64    # arm64
        containers =
          let
            mkServiceContainer =
              name: pkg: p:
              let
                # Services with nothing to declare have no entry at all, which
                # is the common case — a bare binary on the distroless base.
                spec = serviceSpecs.${name} or { };
              in
              mkContainer {
                inherit name;
                packages = [ pkg ];
                # `runtime` is a function of the package set so one spec serves
                # both architectures; see nix/services/default.nix.
                runtime = if spec ? runtime then spec.runtime p else [ ];
                extraCommands = spec.extraCommands or "";
                optCarbideAliases = spec.optCarbideAliases or [ ];
                optCarbideDirs = spec.optCarbideDirs or [ ];
                entrypoint = spec.entrypoint or null;
                cmd = spec.cmd or null;
                meta = carbideMeta;
              };

            # Static-file containers — no compiled binary, just staged trees.
            # They flow through mkServiceContainer unchanged because it only
            # needs a derivation to place in `packages`.
            machineValidationServices = {
              machine-validation-runner = machineValidationFiles.runnerFiles;
              machine-validation-config = machineValidationFiles.configFiles;
              boot-artifacts-x86-64 = bootArtifactsFiles;
            };

            # amd64 — native binaries + native runtime.
            nativeServices =
              nativeRustBinaries // restApiBinariesNative // machineValidationServices;
            amd64Containers = pkgs.lib.mapAttrs' (
              name: pkg:
              pkgs.lib.nameValuePair "${name}-container" (mkServiceContainer name pkg pkgs)
            ) nativeServices;

            # arm64 — cross-compiled server binaries + cross runtime packages.
            # DPU-specific binaries (forge-dpu-agent, carbide-fmds, forge-dhcp-server)
            # already live in aarch64Binaries; server binaries are in aarch64ServerBinaries.
            aarch64Services = aarch64ServerBinaries // {
              inherit (aarch64Binaries) forge-dpu-agent carbide-fmds forge-dhcp-server;
              transceiver-exporter = transceiverExporterAarch64;
              otelcol-contrib      = otelcolContribAarch64;
              # Arch-independent file trees; only the wrapping image differs.
              # CI publishes machine_validation-aarch64, so the config image
              # needs an arm64 variant. The runner image is x86-only, matching
              # Dockerfile.machine-validation-runner.
              machine-validation-config = machineValidationFiles.configFiles;
            } // restApiBinariesFor "arm64";
            arm64Containers = pkgs.lib.mapAttrs' (
              name: pkg:
              pkgs.lib.nameValuePair "${name}-container-arm64"
                (mkServiceContainer name pkg aarch64CrossPkgs)
            ) aarch64Services;

            # Specs are looked up by service name, so the two sides have to
            # agree exactly. A spec whose name matches no service is never
            # consulted, and a service with no spec silently takes every
            # default — both produce an image that is wrong in a way nothing
            # reports until it fails at runtime.
            builtServiceNames = builtins.attrNames (nativeServices // aarch64Services);
            declaredServiceNames = builtins.attrNames serviceSpecs;

            undeclared = pkgs.lib.subtractLists declaredServiceNames builtServiceNames;
            unmatched = pkgs.lib.subtractLists builtServiceNames declaredServiceNames;

          in
          assert pkgs.lib.assertMsg (undeclared == [ ]) ''
            These services build a container but have no entry in nix/services/default.nix:
              ${builtins.concatStringsSep ", " undeclared}
            Add one. Use `{ }` if the binary alone is the whole image.
          '';
          assert pkgs.lib.assertMsg (unmatched == [ ]) ''
            nix/services/default.nix declares services that no container builds:
              ${builtins.concatStringsSep ", " unmatched}
            Check for a typo, or remove the entry if the service is gone.
          '';
          amd64Containers // arm64Containers;

        # ====================================================================
        # Deb packages — binaries that run directly on bare-metal Ubuntu Noble
        # hosts where containers are not an option (e.g. the scout initramfs).
        # ====================================================================
        debs = import ./nix/deb/debs.nix {
          inherit pkgs mkDebPackage nativeRustBinaries;
          carbideScoutAarch64 = carbide-scout-aarch64;
          forgeScoutServiceFile = ./crates/scout/misc/forge-scout.service;
          forgeScoutPostinst = ./crates/scout/misc/DEBIAN/postinst;
        };

        # ====================================================================
        # iPXE EFI bootloader for x86_64.
        #
        # When upstream iPXE is bumped, update both ipxeRev and ipxeHash.
        # First build with a new rev fails with a hash mismatch — copy
        # the reported hash into ipxeHash and rebuild.
        # ====================================================================
        # Shared inputs for both iPXE arches (commit pin and config headers).
        # Each arch picks its own patch set based on what it actually needs.
        ipxeRev = "bbd7821bd42da5456ee068a471ef73d525ea26a1";
        ipxeHash = "sha256-5jzKYvIPkOP1Z7t7OsvmAaY0BI7g793jTh8MfrPpfP8=";
        ipxeConfigHeaders = [
          ./pxe/ipxe/local/branding.h
          ./pxe/ipxe/local/general.h
          ./pxe/ipxe/local/settings.h
        ];

        ipxe-efi-x86 = import ./nix/boot/ipxe-x86.nix {
          inherit
            pkgs
            ipxeRev
            ipxeHash
            ipxeConfigHeaders
            ;
          ipxePatches = [
            ./pxe/ipxe/local/0001-efi-Add-TPM-measurement-API-via-TCG-v1-and-TCG-v2-EF.patch
	    ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          bannerVersion = "carbide-${version}";
          # Without EMBED= the EFI image runs only iPXE's built-in per-NIC
          # autoboot and falls through to "Nothing to boot" — no boot script
          # means no carbide DHCP next-server/filename handoff.
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # ====================================================================
        # iPXE EFI bootloader for aarch64.
        #
        # Cross-compiled from x86_64 build hosts using
        # pkgsCross.aarch64-multiplatform.gcc13Stdenv. Shares the same patch
        # set as the x86 build: TPM measurement, BlueField NIC boot, and the
        # EFI watchdog fix.
        # ====================================================================
        ipxe-efi-aarch64 = import ./nix/boot/ipxe-aarch64.nix {
          inherit
            pkgs
            ipxeRev
            ipxeHash
            ipxeConfigHeaders
            ;
          ipxePatches = [
            ./pxe/ipxe/local/0001-efi-Add-TPM-measurement-API-via-TCG-v1-and-TCG-v2-EF.patch
	    ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          bannerVersion = "carbide-${version}";
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # carbide-scout cross-compiled for aarch64. Consumed by the
        # forge-scout-deb-arm64 deb package defined in nix/deb/debs.nix.
        carbide-scout-aarch64 = mkCrossCrateBinary { pname = "carbide-scout"; };

        # ====================================================================
        # Scout discovery environment as a NixOS netboot UKI
        #
        # An alternative to the mkosi-built scout.efi + scout.cpio.zst pair.
        # One file rather than two, and no Ubuntu archive is consulted at
        # build time. Published to the same path the iPXE templates already
        # reference, so carbide-pxe needs no change to serve it.
        # ====================================================================
        scoutNixosSystem = nixpkgs.lib.nixosSystem {
          # The module takes forgeScout rather than reaching into the flake so
          # that the same configuration can be evaluated against a cross
          # package set for the aarch64 variant.
          specialArgs = {
            forgeScout = nativeRustBinaries.carbide-scout;
            scoutVersion = version;
          };
          modules = [
            ./nix/os/scout.nix
            ./nix/os/scout-nvidia.nix
            { nixpkgs.hostPlatform = system; }
          ];
        };

        # The root filesystem the loader fetches over HTTP, replacing the
        # scout-oss profile's scout.squashfs. Staged into the webroot by
        # `cargo make --cwd pxe scout-x86_64-from-nix`.
        scout-store = import ./nix/os/scout-store.nix {
          inherit pkgs;
          nixosSystem = scoutNixosSystem;
        };

        # The boot-artifacts payload, assembled from the derivations above
        # rather than from whatever is staged in pxe/static/blobs/internal.
        # Wrapped into a carrier image below, replacing
        # dev/docker/Dockerfile.release-artifacts-x86_64.
        bootArtifactsFiles = import ./nix/container/boot-artifacts.nix {
          inherit pkgs;
          arch = "x86_64";
          ipxe = ipxe-efi-x86;
          scoutLoader = scout-loader;
          scoutStore = scout-store;
          scoutSystem = scoutNixosSystem.config.system.build.toplevel;
        };

        # The small image iPXE boots, which fetches scout-store and pivots into
        # it. Replaces the scout-loader mkosi profile; published as scout.efi.
        scoutLoaderSystem = nixpkgs.lib.nixosSystem {
          modules = [
            ./nix/os/scout-loader.nix
            { nixpkgs.hostPlatform = system; }
          ];
        };

        scout-loader = import ./nix/os/uki.nix {
          inherit pkgs;
          nixosSystem = scoutLoaderSystem;
          name = "scout-loader";
        };
      in
      {
        # ==================================================================
        # Packages — `nix build .#<name>`
        # ==================================================================

        packages =
          if system == "x86_64-linux" then
            # x86 server-side binaries (native) + aarch64 DPU/server binaries
            # (cross-compiled) + rest-api Go binaries (both arches via
            # GOARCH) merged into one attribute set. No name overlap — every
            # binary has a unique attribute name. From an x86 dev machine,
            # `nix build .#forge-dpu-agent` cross-compiles to aarch64;
            # `nix build .#rest-api-api-aarch64` cross-compiles Go to arm64.
            nativeRustBinaries
            // aarch64Binaries
            // restApiBinariesAmd64
            // restApiBinariesArm64
            // containers
            // debs
            // {
              inherit
                ipxe-efi-x86
                ipxe-efi-aarch64
                carbide-scout-aarch64
                scout-store
                scout-loader
                ;

              # Expose the deps-only derivation so CI can cache it directly.
              # `nix build .#deps` builds just the dep phase — useful for
              # warming the binary cache after Cargo.lock changes.
              deps = cargoArtifacts;
            }
          else if system == "aarch64-linux" then
            # Native aarch64 build host. nativeRustBinaries/aarch64Binaries both
            # evaluate against aarch64 `pkgs` here, producing aarch64
            # binaries; the cross-compile path (mkCrossCrateBinary) becomes
            # a no-op cross since target = host. rest-api Go binaries:
            # amd64 set still needs cross (GOARCH=amd64 from aarch64 host).
            nativeRustBinaries
            // aarch64Binaries
            // restApiBinariesAmd64
            // restApiBinariesArm64
            // containers
            // {
              inherit
                ipxe-efi-aarch64
                ;
            }
          else
            { };

        # Runnable targets — `nix run .#<name>`. Each app family lives in its
        # own file under nix/apps/; see those files for what they do.
        #
        # Linux-only: both families operate on container images, and
        # nix2container's skopeo `nix:` transport is not available on Darwin.
        # Multi-arch manifest creation is handled in CI via crane/skopeo directly.
        apps = pkgs.lib.optionalAttrs isLinux (
          let
            # Both app families take the amd64 images only — see
            # nix/apps/copy-to-docker.nix for why.
            appArgs = {
              inherit pkgs;
              containers = pkgs.lib.filterAttrs (n: _: !(pkgs.lib.hasSuffix "-arm64" n)) containers;
            };
          in
          import ./nix/apps/copy-to-docker.nix appArgs // import ./nix/apps/sbom.nix appArgs
        );

        # ==================================================================
        # Dev shell — `nix develop`
        # ==================================================================

        devShells.default = craneLib.devShell (
          {
            packages =
              (with pkgs; [
                # `just check-licenses` / `just check-bans` shell out to this.
                cargo-deny
                cargo-make
                cargo-nextest
                # The justfile is the entry point for builds and lints, and CI
                # runs it as `nix develop --command just <recipe>` — so the
                # shell has to provide it.
                just
                sccache
                sqlx-cli
                taplo
                # Go toolchain matches rest-api/go.mod's `go 1.25.4`. Plus
                # gopls / delve for editor LSP and debugging.
                go_1_25
                gopls
                delve
              ])
              # Runtime tools (kea, ipmitool, tpm2-tools, etc.) are Linux-only.
              ++ pkgs.lib.optionals isLinux runtimeTools;

            # Dev shell needs the full library set so contributors can build
            # any crate via `cargo build`, not just one specific binary.
            # tpm2-tss and other Linux-only libs are excluded on Darwin via
            # allBuildInputs already being gated.
            # Unlike a per-binary derivation, the dev shell has to build every
            # crate. carbide-dhcp's build.rs compiles C++ against Kea's headers,
            # and those #include <boost/...>, so both are needed here. Binary
            # derivations pick them up from dhcpCrateExtraArgs instead.
            buildInputs =
              allBuildInputs
              ++ pkgs.lib.optionals isLinux [
                pkgs.kea
                pkgs.boost.dev
              ];
            inherit nativeBuildInputs;

            # Nix's stdenv injects -D_FORTIFY_SOURCE by default, but that
            # requires -O1 or better. cargo's dev profile compiles the Kea C++
            # shim (crates/dhcp/build.rs -> cc-rs) at -O0, so every debug build
            # prints a wall of "#warning _FORTIFY_SOURCE requires compiling
            # with optimization" from glibc's features.h. It is noise, not a
            # miscompile — fortification is simply inert at -O0.
            #
            # Scoped to the dev shell on purpose: package builds go through
            # crane in release mode, where -O is on, fortification is real, and
            # this warning never fires. Disabling it globally would weaken the
            # binaries we actually ship.
            hardeningDisable = [ "fortify" ];

            # Route cargo compilations through sccache. First run populates
            # the cache; subsequent builds of the same source (across
            # branches, checkouts, rebuilds) get cache hits at the individual
            # object file level.
            RUSTC_WRAPPER = "sccache";

            # sccache finds its background server by port and its cache by
            # SCCACHE_DIR. At the defaults the dev shell's sccache will try to
            # use whichever server is already running — including one started
            # by a different sccache installed on the host. The versions then
            # disagree on the wire protocol and every compile dies with
            # "error reading compile response from server", which reads like a
            # compiler error but is not. Give the Nix sccache its own port and
            # cache directory so the two can coexist. Both are overridable.
            shellHook = ''
              export SCCACHE_DIR="''${SCCACHE_DIR:-$HOME/.cache/sccache-nix}"
              export SCCACHE_SERVER_PORT="''${SCCACHE_SERVER_PORT:-4227}"
            '';

            SQLX_OFFLINE = "true";
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            PROTOC_INCLUDE = "${pkgs.protobuf}/include";

            # Nightly tooling for the lint tasks, supplied by Nix rather than
            # rustup. `cargo fmt` honours RUSTFMT, so the format tasks need no
            # `+toolchain` shim; CARGO_NIGHTLY is used to build carbide-lints.
            # The cargo-make tasks fall back to `cargo +${RUST_NIGHTLY}` when
            # these are unset, so rustup-based workflows keep working.
            RUSTFMT = "${rustNightlyToolchain}/bin/rustfmt";
            CARGO_NIGHTLY = "${rustNightlyToolchain}/bin/cargo";
          }
          // pkgs.lib.optionalAttrs isLinux {
            KEA_INCLUDE_PATH = "${pkgs.kea}/include/kea";
            # Same shim the package builds use — see mkKeaLibShim.
            KEA_LIB_PATH = "${mkKeaLibShim pkgs}/lib";

            # Ensure dev-shell aarch64 cross-builds use the same 64KB-page-
            # compatible max-page-size as `nix build`. ARM64 server hardware
            # (NVIDIA Grace, certain Ampere SKUs) runs 64KB-page kernels;
            # binaries linked with the default 4KB segment alignment can
            # load incorrectly there. Target-suffixed env var → no effect
            # on native x86 builds.
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";
          }
        );
      }
    );
}

