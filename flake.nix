/*
  About the nix language and flakes:
  https://nix.dev/tutorials/nix-language
  https://nix.dev/manual/nix/2.26/language/

  A handy search engine for nixpkgs lib function is https://noogle.dev

  The nix language is a functional programming language, some of the key properties of the nix language:

  1. Functions are first class values - you can pass them as arguments and return them from other functions.
  e.g. `rustToolchainFor` is a plain value that happens to be a function
  2. Everything is an expression - there are no statements, no mutation, no loops.  `if`, `let` and `with` all evaluate to values.
  In imperative languages, `if` is a statement - it executes code but doesn't produce a value.  In Nix, `if` always evaluates to a value:

  ```
  buildInputs = if pkgs.stdenv.isLinux then [ pkgs.libudev ] else [];
  ```

  `let` is the same - it's not a block of statements, it's an expression that evaluates to whatever comes after `in`:

  ```
  let
    x = 5;
    label = if x > 3 then "big" else "small";
  in
  label  # -> "big"
  ```
  3. Immutable - you can't modify a variable after binding it. `//` doesn't mutate an attrset, it produces a new one.
  4. Lazy evaluation - expressions are only evaluated when their value is actually needed. This is why a large flake
  (like this one) with many derivations and packages doesn't build everything up front.

  Caveat to "functional programming language": Nix is a domain-specific functional language. It only exists to describe
  package builds, not general computation. It has no type system, no IO (beyond derivations) and a very small set of built-in types:
  e.g. strings, integers, lists, attrsets, paths, functions, derivations


  Flakes themselves are basically one big `let ... in` block.

  Nix functions are defined with a colon. The syntax is `argument: body`
  ```
   x: x + 1   # This function takes x and returns x + 1. You call it by putting the argument after it:
   (x: x + 1) 5  # -> 6
  ```

  You can assign it a name by binding it in a `let`:
  ```
  let
    addOne = x: x + 1;
  in
  addOne 5 # -> 6
  ```

  Multiple arguments are done by chaining (currying) - each `:` adds one argument:
  ```
  let
    add = x: y: x + y;
  in
  add 3 4  # -> 7
  ```

  Attrset arguments (the most common pattern in nixpkgs and flakes) use destructuring:
  ```
  let
    say = { name, statement }: "${name}. ${statement}!";
  in
  say { name = "Joseph Miller"; statement = "it reaches out"; }
  ```

  This is what you will see throughout this flake - `{ pkgs, system, version, ... }: ...` is a function that takes an
  attrset and destructures named fields out of it.  The `...` means "accept extra fields I have not named".

  For a real definition of a function, take a look at `rustToolchainFor` below.

  Some Nix docs use Haskell type signatures. Below is an example from craneLib.overrideToolchain:
  ```
  overrideToolchain :: (set -> drv) -> set
  overrideToolchain :: drv -> set (legacy)
  ```
  Breaking this down:
  ```
  overrideToolchain :: (set -> drv) -> set
  - :: means "has type"
  - (set -> drv) means "a function that takes a set and returns a derivation"
  - -> set means the whole thing returns a set - specifically a new craneLib instance with the toolchain baked in

  So it's saying: "pass in a function from package-set to derivation, get back a new craneLib set"

  overrideToolchain :: drv -> set (legacy)
  This is the older form where you just pass a derivation directly instead of a function.
  ```
*/


# Nix flake for infra-controller
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

    bombon = {
      url = "github:nikstur/bombon";
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
      bombon,
    }:
    /*
      `eachDefaultSystem` is a part of `flake-utils` library and returns a list of systems support by nix.
      that is passed in as system: 
      For documentation on flake-utils https://github.com/numtide/flake-utils
    */
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        # imports nixpkgs as a function cpu/os architecture based on system:
        pkgs = import nixpkgs {
          # pull system into scope
          inherit system;
          # overlays are a list of functions that patch or extend a package set.
          overlays = [
            rust-overlay.overlays.default
          ];
        };

        /*
          Rust toolchain expressed as a function over `pkgs`. Crane wants this so it can splice the toolchain
          through the correct package set when cross-compiling — host vs target — without us pre-binding
          to one or the other. This function takes p (a package set) and returns a toolchain derivation

          The `:` makes this a function. The definition start with `p:` - a function that takes one argument `p` and
          returns p.rust-bin.stable "1.95.0".default.override which is a chain of attribute lookups on `p`
          p.rust-bin - the attrset added by rust-overlay, containing all available Rust toolchains
          .stable - the stable channel (as opposed to nightly)
          ."1.95.0" - the specific version - quotes because it contains dots
          .default - the standard toolchain profile (rustc + cargo + rustfmt + clippy)
          .override { .. } - a nixpkgs convention that lets you customize a derivation without rebuilding it from scratch
          Here it adds extra extensions (rust-src, rust-analyzer) and cross compilation targets on top of the default profile

          In plain English: "from the rust-overlay package set, get stable Rust 1.95.0 with the default profile, then extend it with these extras"
        */
        rustToolchainFor =
          p:
          p.rust-bin.stable."1.95.0".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "aarch64-unknown-linux-gnu"
            ];
          };

        # wire up crane to the rust rustToolchainFor defined above.  All craneLib.* calls will use this
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchainFor;
        # Use nix2container nix library.  mkContainer uses this when building OCI images
        nix2containerLib = nix2container.packages.${system}.nix2container;
        # import nix2container helpers for interfacing with docker daemon
        containerCopyHelpers = import ./nix/container/nix2container-skopeo.nix {
          inherit pkgs;
          skopeoNix2container = nix2container.packages.${system}.skopeo-nix2container;
        };

        # ====================================================================
        # System dependencies
        # ====================================================================
        # nativeBuildInputs are tools that run on the build machine (host), not the target.
        # Contrast with buildInputs, which are libraries linked into the output binary for the target machine.
        nativeBuildInputs = with pkgs; [
          cmake
          clang
          lld
          pkg-config
          protobuf
          # autoPatchelfHook embeds Nix-store paths in RPATH so the binary
          # finds its .so deps without LD_LIBRARY_PATH. Production
          # deployment ships the binaries inside containers via
          # mkContainer, which bundles the full /nix/store closure;
          # /nix/store paths exist inside the image so RPATH resolves
          # cleanly.
          autoPatchelfHook
        ];

        # Union of every C library any crate in the workspace might link.
        #
        # The deps phase (cargoArtifacts) needs this complete set: cargo
        # compiles every external crate including -sys crates whose build.rs
        # calls pkg-config for "their" library. Missing any one library
        # fails the deps phase even if no individual binary needs it.
        #
        # Most package-phase builds still use mkCrateBinary and get this
        # full set. Crates with unusual link requirements should define a
        # focused package expression instead; carbide-dhcp does this for
        # Kea in crates/dhcp/package.nix.
        allBuildInputs = with pkgs; [
          grpc
          #libudev-zero
          #openipmi
          openssl
          #postgresql_15.lib
          tpm2-tss.dev
        ];

        # ====================================================================
        # Source filtering
        # ====================================================================

        # Declare sources additively using filesets. We start with crane's
        # defaults (Cargo.{toml,lock}, .rs files, rust-toolchain.toml)
        # and then add additional non-Rust files as needed. This ensures
        # that changes to .rs files don't invalidate the deps cache,
        # but changes to Cargo.toml or rust-toolchain.toml do.
        # A benefit of being explicit is cache efficiency.  Changing a file outside these paths
        # e.g. A helm chart, or README doesn't invalidate the nix build cache

        # https://noogle.dev/f/lib/fileset/toSource/
        src = pkgs.lib.fileset.toSource {
          root = ./.; 
          # https://noogle.dev/f/lib/fileset/unions/
          fileset = pkgs.lib.fileset.unions [
            # https://crane.dev/API.html?highlight=commoncargoS#cranelibfilesetcommoncargosources
            (craneLib.fileset.commonCargoSources ./.)
            ./crates
            # Non-Rust files outside crates/ referenced at build/test time.
            ./.cargo
            # PXE boot templates referenced by crates via
            # include_str!("").
            ./pxe/templates
          ];
        };

        # Derive version from git. `self` refers to the flake itself
        version = self.shortRev or self.dirtyShortRev or "dev";

        # ====================================================================
        # Common arguments shared by all crane derivations.
        # ====================================================================
        # commonArgs is an attributeSet (aka a map, dictionary) 
        commonArgs = {
          # inherit brings outer bindings into the commonArgs scope
          inherit
            src
            version
            nativeBuildInputs
            ;

          # Note: no buildInputs here. The deps phase and mkCrateBinary inject
          # `allBuildInputs` explicitly below; custom per-crate expressions can
          # provide a narrower package-specific set.
          pname = "carbide-workspace";
          strictDeps = true;
          # Do not run cargo test during the build process. 
          doCheck = false;

          # Workspace-wide env vars.
          # Do not connect to a real database at compile time. Connecting to a real DB break in a Nix sandbox.
          # There is no network, no database available
          # We can look into using `cargo sqlx prepare` on a real database and then checking in the resulting files
          # The downside is if a query changes but we forget to rerun cargo sqlx prepare, the .sqlx/ files go stale
          # and the discrepancy will not be caught until runtime.  We could enforce `cargo sqlx prepare --check` in CI
          SQLX_OFFLINE = "true";
          # Path to protoc binary and include files
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          # Uses clang linker for native x86_64
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "clang";
        };

        # ====================================================================
        # Phase 1: Build only workspace dependencies.
        #
        # This derivation compiles every external crate dependency but none
        # of the carbide source. Input hash depends only on Cargo.lock and
        # Cargo.toml files, so source-only changes get a cache hit here.
        # ====================================================================

        # Deps-only source: just Cargo.toml / Cargo.lock / rust-toolchain.
        # Using this narrower source for buildDepsOnly means changing any
        # .rs file does NOT invalidate the deps cache — only Cargo.lock
        # or workspace Cargo.toml changes do.
        # https://crane.dev/API.html?highlight=cleanCargoSource#cranelibcleancargosource
        depsSrc = craneLib.cleanCargoSource ./.;

        # in nix by convention, any function names build* or mk* returns a derivation rather than
        # a plain attrset.
        # https://crane.dev/API.html?highlight=cranelib.buildDepsOnly#cranelibbuilddepsonly
        # this merged attrset flows through `buildDepsOnly -> mkCargoDerivation -> stdenv.mkDerivation`
        #
        cargoArtifacts = craneLib.buildDepsOnly (
          # include commonArgs in this derivation
          commonArgs
          // {
            # `//` means merge attrsets, with the right side winning on duplicate keys
            # Override source with deps-only source.
            src = depsSrc;
            # You can also add new keys to an attribute set during the merge.  `buildInputs` does not
            # exist in commonArgs. craneLib.buildDepsonly is a wrapper around craneLib.mkCargoDerivation which is a
            # wrapper around stdenv.mkDerivation. This is a common pattern in nixpkgs - functions that wrap mkDerivation
            # typicall accept `...` to forward unknown arguments straight through.
            # https://nixos.org/manual/nixpkgs/stable/#var-stdenv-buildInputs

            # Deps phase compiles every external -sys crate; needs the
            # full library union so each one's build.rs finds its target
            # via pkg-config.
            buildInputs = allBuildInputs;
          }
        );


        # imports create-binary and binds it to mkCrateBinary
        # Build one native workspace binary while reusing the deps only build from cargoArtifacts
        mkCrateBinary = import ./nix/rust/crate-binary.nix {
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
        # Pin the cross stdenv to gcc 13 to match ipxe-x86's gcc13Stdenv and
        # Ubuntu 24.04's default gcc. Without this, pkgsCross would default to
        # gcc 14, creating an inconsistency between iPXE binaries and Rust
        # binaries inside the same release.
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

        dhcpCrateExtraArgs = dhcpPkgs: {
          buildInputs = with dhcpPkgs; [
            stdenv.cc.cc.lib
            kea
            boost.dev
          ];
          postConfigure = ''
            mkdir -p $TMPDIR/kea-lib
            ln -sf ${dhcpPkgs.kea}/lib/libkea-*.so* $TMPDIR/kea-lib
            ln -sf ${dhcpPkgs.kea}/lib/libkea-dhcp.so $TMPDIR/kea-lib/libkea-dhcp++.so
            export KEA_LIB_PATH="$TMPDIR/kea-lib"
          '';
          KEA_INCLUDE_PATH = "${dhcpPkgs.kea}/include/kea";
          KEA_LIB_PATH = "${dhcpPkgs.kea}/lib";
        };

        # ====================================================================
        # Per-architecture binary sets
        # ====================================================================

        # Shared metadata applied to every carbide workspace binary.
        # bombon reads meta.license and meta.homepage to populate
        # the licenseDeclared / downloadLocation fields in generated SBOMs.
        carbideMeta = {
          license = pkgs.lib.licenses.asl20;
          homepage = "https://github.com/NVIDIA/infra-controller";
          maintainers = [ ];
        };

        nativeRustBinaries = {
          carbide-api = mkCrateBinary { pname = "carbide-api"; meta = carbideMeta; };
          carbide-dns = mkCrateBinary { pname = "carbide-dns"; meta = carbideMeta; };
          carbide-pxe = mkCrateBinary { pname = "carbide-pxe"; meta = carbideMeta; };
          carbide-dhcp = mkCrateBinary {
            pname = "carbide-dhcp";
            meta = carbideMeta;
            extraArgs = dhcpCrateExtraArgs pkgs;
          };
          carbide-dsx-exchange-consumer = mkCrateBinary { pname = "carbide-dsx-exchange-consumer"; meta = carbideMeta; };
          carbide-admin-cli = mkCrateBinary { pname = "carbide-admin-cli"; meta = carbideMeta; };
          carbide-health = mkCrateBinary { pname = "carbide-health"; meta = carbideMeta; };
          carbide-ssh-console = mkCrateBinary { pname = "carbide-ssh-console"; meta = carbideMeta; };

          # carbide-scout produces a binary named "forge-scout" (per the
          # crate's [[bin]] target); downstream packaging wraps it as needed.
          carbide-scout = mkCrateBinary { pname = "carbide-scout"; meta = carbideMeta; };
        };

        nativeRustBinariesWithSbom = pkgs.lib.mapAttrs (
          _name: pkg:
            bombon.lib.${system}.passthruVendoredSbom.rust pkg  { inherit pkgs; }
        ) nativeRustBinaries;

        rustSboms = pkgs.lib.mapAttrs' (
         name: pkg: pkgs.lib.nameValuePair "${name}-sbom"
           (bombon.lib.${system}.buildBom pkg { includeBuildtimeDependencies = false; })
        ) nativeRustBinariesWithSbom;

        # Container SBOMs: one per service image, covering both the carbide
        # binary (license from cargo metadata via passthruVendoredSbom) and
        # every runtime package in the container closure (license from nixpkgs
        # metadata).
        #
        # buildBom is called on the Rust binary (sbomPackages[0]) with the
        # runtime deps as extraPaths — same pattern as the in-container
        # attribution file. See the attributionSbom comment in mkContainer.
        containerSboms = pkgs.lib.mapAttrs' (
          name: container:
          let
            pkgs_ = container.passthru.sbomPackages;
            rt = container.passthru.sbomRuntime;
          in
          pkgs.lib.nameValuePair "${name}-sbom"
            (bombon.lib.${system}.buildBom (builtins.head pkgs_) {
              includeBuildtimeDependencies = false;
              extraPaths = pkgs.lib.tail pkgs_ ++ rt ++ [ pkgs.cacert ];
            })
        ) containers;

        # aarch64 binaries are cross-compiled via mkCrossCrateBinary. Build
        # host can be either x86_64 or aarch64 — pkgsCross.aarch64-
        # multiplatform resolves to a real cross gcc on x86 hosts and to
        # the native aarch64 gcc on aarch64 hosts (see the cache-slot
        # comment above mkCrossCrateBinary).
        #
        # The cargo PACKAGE names are `carbide-*` but each crate's [[bin]]
        # target renames the BINARY to `forge-*` — so we build by package
        # name and the resulting $out/bin/ contains the forge-* binary
        # downstream consumers (BFB packaging, k8s charts) expect.
        aarch64Binaries = {
          carbide-dpf = mkCrossCrateBinary { pname = "carbide-dpf"; cargoExtraArgs = "--features driver --bin carbide-dpf-api-harness"; };
          forge-dpu-agent = mkCrossCrateBinary { pname = "carbide-agent"; };
          forge-dhcp-server = mkCrossCrateBinary { pname = "carbide-dhcp-server"; };
          carbide-fmds = mkCrossCrateBinary { pname = "carbide-fmds"; };
        };

        # ====================================================================
        # Go binaries (rest-api workspace)
        # ====================================================================
        #
        # The rest-api/ tree is a single Go module (rest-api/go.mod) with a
        # `replace` directive pointing at the in-tree rest-api/sdk/standard
        # submodule; `buildGoModule`'s default `proxyVendor` mode handles the
        # path replace correctly.
        #
        # Each production binary lives at a `<service>/cmd/<binary>/main.go`
        # path; we build them with `CGO_ENABLED=0` + `-extldflags '-static'`,
        # which is what rest-api/Makefile does for production. Static Go
        # binaries make raw syscalls directly — no glibc, no ELF interpreter
        # to patchelf, so they run on any Linux of the matching arch
        # (Noble, alpine, distroless, BFB initramfs, anywhere). Cross-compile
        # to aarch64 is trivial: just flip GOARCH.

        # Vendor hash for the rest-api Go module. TOFU on first build:
        #   1. Set to `pkgs.lib.fakeHash` (already so below).
        #   2. Run `nix build .#rest-api-api` — the build fails at vendoring
        #      with a "hash mismatch" error printing the expected sha256.
        #   3. Copy that sha256 here and rebuild.
        # All rest-api binaries share this — they all live under the same
        # go.mod, so vendoring is identical for each.
        restApiVendorHash = pkgs.lib.fakeHash;

        # Source for rest-api builds. ./rest-api wraps the whole sub-tree;
        # changes to anything under it (.go files, go.mod, sdk/standard/)
        # invalidate the build. We don't bother filtering further today —
        # if iteration speed becomes a problem, replace with a fileset that
        # excludes test data / docs.
        restApiSrc = ./rest-api;

        mkGoBinary =
          {
            pname,
            subPackage, # path relative to rest-api/, e.g. "api/cmd/api"
            binaryName ? null, # filename inside $out/bin; defaults to baseNameOf subPackage
            goarch ? "amd64", # "amd64" or "arm64"
          }:
          let
            defaultName = baseNameOf subPackage;
            outName = if binaryName == null then defaultName else binaryName;
          in
          pkgs.buildGoModule ({
            inherit pname version;
            src = restApiSrc;
            vendorHash = restApiVendorHash;
            subPackages = [ subPackage ];

            # Static + no libc dep. Same flags rest-api/Makefile uses for
            # production.
            env.CGO_ENABLED = "0";
            env.GOOS = "linux";
            env.GOARCH = goarch;
            ldflags = [ "-extldflags '-static'" ];

            # buildGoModule names the output after the last path component of
            # subPackage (e.g. "api/cmd/api" → bin/api). Rename when the
            # Makefile uses a `-o <name>` that differs (e.g. cli/cmd/cli →
            # nicocli).
            postInstall = pkgs.lib.optionalString (outName != defaultName) ''
              mv $out/bin/${defaultName} $out/bin/${outName}
            '';

            meta.mainProgram = outName;
          });

        # Per-arch rest-api binary sets. The set of cmd packages mirrors
        # `rest-api/Makefile` lines 197-203.
        restApiBuildSpec = [
          {
            pname = "rest-api-api";
            subPackage = "api/cmd/api";
          }
          {
            pname = "rest-api-workflow";
            subPackage = "workflow/cmd/workflow";
          }
          {
            pname = "rest-api-sitemgr";
            subPackage = "site-manager/cmd/sitemgr";
          }
          {
            pname = "rest-api-site-agent";
            subPackage = "site-agent/cmd/site-agent";
          }
          {
            pname = "rest-api-migrations";
            subPackage = "db/cmd/migrations";
          }
          {
            pname = "rest-api-credsmgr";
            subPackage = "cert-manager/cmd/credsmgr";
          }
          {
            # Source is cli/cmd/cli/ but the Makefile names the binary
            # `nicocli`. buildGoModule would name it `cli` by default; rename
            # via mkGoBinary's binaryName.
            pname = "rest-api-nicocli";
            subPackage = "cli/cmd/cli";
            binaryName = "nicocli";
          }
        ];

        # Attrset of {<pname>: derivation} for each goarch.
        restApiBinariesFor =
          goarch:
          pkgs.lib.listToAttrs (
            map (spec: {
              name = spec.pname;
              value = mkGoBinary (spec // { inherit goarch; });
            }) restApiBuildSpec
          );

        containerGoarch = if system == "aarch64-linux" then "arm64" else "amd64";
        restApiBinariesNative = restApiBinariesFor containerGoarch;
        restApiBinariesAmd64 = restApiBinariesFor "amd64";
        # The arm64 set gets `-aarch64` suffixed names so amd64 + aarch64
        # don't collide when both are exposed from the same packages output.
        restApiBinariesArm64 = pkgs.lib.mapAttrs' (
          name: drv: pkgs.lib.nameValuePair "${name}-aarch64" drv
        ) (restApiBinariesFor "arm64");

        # CLI tools exposed by `nix develop`. Container runtime tools are
        # selected separately in `serviceRuntime` so each image only carries
        # the shell-out utilities it actually needs.
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
        # Container builder
        # ====================================================================
        #
        # Wraps a binary (or several) and a per-service runtime closure into
        # one image. nix2container writes OCI-native image metadata and exposes
        # copy helpers, so CI can push directly without a separate image-load
        # step.
        #
        # `copyToRoot` receives a buildEnv that merges each package's standard
        # runtime paths into the image root, so every binary ends up at
        # /bin/<name> and package-owned config/cert directories are available
        # at their normal FHS locations. nix2container also layers the full
        # /nix/store closure of each package (glibc, libssl, libudev, etc.),
        # so binaries built with autoPatchelfHook's /nix/store RPATH find
        # their .so deps inside the image.
        #
        # The split between `packages` and `runtime` is purely conventional:
        #
        #   - `packages` = the binaries this container is built around.
        #   - `runtime`  = extra tools / libraries / shell-out targets the
        #                  binaries need at runtime. Empty by default.
        #
        # Both end up in the `copyToRoot` root environment so the image is
        # the same shape either way; the named-parameter split just makes
        # intent legible at the call site. `extraContents` is for arbitrary
        # non-binary inputs (config files, certs, etc.); `extraCommands` is
        # opaque shell baked into the image root at build time.
        #
        # Examples:
        #
        #   mkContainer {                 # bare binary, no extras
        #     name = "rest-api-api";
        #     packages = [ rest-api-api ];
        #   };
        #
        #   mkContainer {                 # service that shells out to kea
        #     name = "carbide-dhcp";
        #     packages = [ carbide-dhcp ];
        #     runtime  = [ pkgs.kea pkgs.iproute2 ];
        #     extraCommands = "mkdir -p var/run/kea";
        #   };
        #

        mkOssSources = import ./nix/container/oss-sources.nix { inherit pkgs; };

        mkContainer = import ./nix/container/make-container.nix {
          inherit
            pkgs
            nix2containerLib
            containerCopyHelpers
            bombon
            system
            version
            mkOssSources
            ;
        };

        # Per-service runtime requirements. Each entry overrides the default
        # empty runtime for that container; unlisted services get no extras
        # beyond the binary's own /nix/store closure. Add entries as
        # downstream deployment confirms what each binary needs to shell out
        # to at runtime.
        #
        # `serviceExtraCommands` parallels this for any per-service shell
        # one-liners that need to run at image build time (e.g. pre-creating
        # a pid/lock directory).
        serviceRuntime = {
          # Examples — uncomment / extend per real deployment needs:
          #
	        carbide-dns = with pkgs; [
	          busybox
          ];
          carbide-pxe = with pkgs; [
            busybox
          ];
          carbide-dhcp = with pkgs; [
            kea
            busybox
          ];
          # carbide-scout = with pkgs; [ tpm2-tools ipmitool ];
          carbide-api = with pkgs; [
            tpm2-tools
            ipmitool
            busybox
            iputils
            iproute2
          ];
        };

        serviceExtraCommands = {
          carbide-dhcp = "mkdir -p var/run/kea";
        };

        # Per-service containers — one image per binary, mirroring CI's
        # `release-container-*` / `nico-rest-*` / bluefield containers.
        # Each is auto-generated from a binary derivation; the container
        # name (= image tag) matches the binary's attribute name.
        #
        # Exposed at `nix build .#<binary>-container`. For example:
        #
        #   nix build .#carbide-api-container        # carbide-api binary
        #   nix build .#rest-api-api-container       # nico-rest-api equivalent
        #   nix build .#carbide-admin-cli-container  # forge-cli equivalent
        #
        # Naming uses the `-container` suffix to disambiguate from the
        # bare-binary outputs of the same name (`nix build .#carbide-api`
        # is just the executable, no container wrapper).
        #
        # Containers use binaries and runtime tools for the current flake
        # system: x86_64-linux produces amd64 images, and aarch64-linux
        # produces arm64 images. Cross-built DPU artifacts remain exposed as
        # bare packages and are wrapped by downstream packaging where needed.
        containers =
          let
            mkServiceContainer =
              name: pkg:
              mkContainer {
                inherit name;
                packages = [ pkg ];
                runtime = serviceRuntime.${name} or [ ];
                extraCommands = serviceExtraCommands.${name} or "";
                meta = carbideMeta;
              };

            # Services that ship as containers in production: all native
            # carbide-* server binaries + native Go rest-api binaries.
            # Use nativeRustBinariesWithSbom so bombon can find cargo-derived
            # license metadata for our binaries when it walks the container closure.
            nativeServices = nativeRustBinariesWithSbom // restApiBinariesNative;

            perService = pkgs.lib.mapAttrs' (
              name: pkg: pkgs.lib.nameValuePair "${name}-container" (mkServiceContainer name pkg)
            ) nativeServices;

          in
          perService;

        # ====================================================================
        # iPXE EFI bootloader for x86_64.
        #
        # When upstream iPXE is bumped, update both ipxeRev and ipxeHash.
        # First build with a new rev fails with a hash mismatch — copy
        # the reported hash into ipxeHash and rebuild.
        # ====================================================================
        # Shared inputs for both iPXE arches (commit pin and config headers).
        # Each arch picks its own patch set based on what it actually needs.
        ipxeRev = "d7e58c5a812988c341ec4ad19f79faf067388d58";
        ipxeHash = "sha256-OIisRd2o2zrTqH1Xv3FDhQWDqhKNeGhPkHWyYZzbtTU=";
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
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          bannerVersion = "carbide-${version}";
          # Mirrors cargo-make's EMBED=${REPO_ROOT}/pxe/ipxe/local/embed.ipxe.
          # Without this the EFI image only runs iPXE's built-in autoboot
          # and falls through to "Nothing to boot" — see SESSION.md.
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # ====================================================================
        # iPXE EFI bootloader for aarch64.
        #
        # Cross-compiled from x86_64 build hosts using
        # pkgsCross.aarch64-multiplatform.gcc13Stdenv. The aarch64 patches
        # (mlnx, grace-grace, efi-rng) target hardware-specific issues:
        # BlueField NIC boot, Supermicro Grace/Grace, and ARM EFI RNG.
        # ====================================================================
        ipxe-efi-aarch64 = import ./nix/boot/ipxe-aarch64.nix {
          inherit
            pkgs
            ipxeRev
            ipxeHash
            ipxeConfigHeaders
            ;
          ipxePatches = [
            ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
            ./pxe/ipxe/local/0002-fix-for-grace-grace.patch
            ./pxe/ipxe/local/0004-efi-retry-rng.patch
          ];
          bannerVersion = "carbide-${version}";
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # carbide-scout cross-compiled for aarch64. Shipped to downstream
        # packaging by some other means than Nix today; produced here as
        # a bare binary.
        carbide-scout-aarch64 = mkCrossCrateBinary { pname = "carbide-scout"; };
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
            // rustSboms
            // containerSboms
            // {
              inherit
                ipxe-efi-x86
                ipxe-efi-aarch64
                carbide-scout-aarch64
                ;

              # Expose the deps-only derivation so CI can cache it directly.
              # `nix build .#deps` builds just the dep phase — useful for
              # warming the binary cache after Cargo.lock changes.
              deps = cargoArtifacts;

              # Kea is not cross-compile friendly in nixpkgs because its Meson
              # configure checks execute target binaries. Keep this convenience
              # target available from x86_64, but make it build the aarch64
              # flake output so Nix uses an aarch64 builder or substituter.
              # Its nix2container copy helpers remain aarch64-native too; only
              # containers that can be produced in the x86_64 package set get
              # x86_64-native copy helpers.
              carbide-dhcp-container-aarch64 = self.packages.aarch64-linux.carbide-dhcp-container;
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
            // rustSboms
            // containerSboms
            // {
              inherit
                ipxe-efi-aarch64
                ;
            }
          else
            { };

        # One app per container: `nix run .#<name>-container-copy-to-docker`
        # loads the image into the local Docker daemon via the patched
        # skopeo nix: transport.
        apps = pkgs.lib.mapAttrs' (
          name: container:
          pkgs.lib.nameValuePair "${name}-copy-to-docker" {
            type = "app";
            program = "${container.passthru.copyToDockerDaemon}/bin/copy-to-docker-daemon";
          }
        ) containers;

        # ==================================================================
        # Dev shell — `nix develop`
        # ==================================================================

        devShells.default = craneLib.devShell {
          packages =
            (with pkgs; [
              cargo-make
              cargo-nextest
              sccache
              sqlx-cli
              taplo
              # Go toolchain matches rest-api/go.mod's `go 1.25.4`. Plus
              # gopls / delve for editor LSP and debugging.
              go_1_25
              gopls
              delve
            ])
            ++ runtimeTools;

          # Dev shell needs the full library set so contributors can build
          # any crate via `cargo build`, not just one specific binary.
          buildInputs = allBuildInputs;
          inherit nativeBuildInputs;

          # Route cargo compilations through sccache. First run populates
          # the cache at ~/.cache/sccache; subsequent builds of the same
          # source (across branches, checkouts, rebuilds) get cache hits
          # at the individual object file level.
          RUSTC_WRAPPER = "sccache";

          SQLX_OFFLINE = "true";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          KEA_INCLUDE_PATH = "${pkgs.kea}/include/kea";
          KEA_LIB_PATH = "${pkgs.kea}/lib";

          # Ensure dev-shell aarch64 cross-builds use the same 64KB-page-
          # compatible max-page-size as `nix build`. ARM64 server hardware
          # (NVIDIA Grace, certain Ampere SKUs) runs 64KB-page kernels;
          # binaries linked with the default 4KB segment alignment can
          # load incorrectly there. Target-suffixed env var → no effect
          # on native x86 builds.
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";
        };
      }
    );
}

