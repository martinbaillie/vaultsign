let
  sources = import ./nix/sources.nix;
  rust = import ./nix/rust.nix { inherit sources; };
  pkgs = import sources.nixpkgs { };
in with pkgs;
mkShell {
  shellHook = ''
    export NIX_BUILD_SHELL=${pkgs.bashInteractive}/bin/bash
  '';
  buildInputs = [
    bashInteractive
    cacert
    curl
    git
    killall
    pkg-config
    rust
    unzip
    vault
    which
    openssl
  ] ++ stdenv.lib.optionals stdenv.isDarwin
    [ darwin.apple_sdk.frameworks.Security ];
  RUST_BACKTRACE = 1;
}
