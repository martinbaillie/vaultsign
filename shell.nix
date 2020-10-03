let
  sources = import ./nix/sources.nix;
  rust = import ./nix/rust.nix { inherit sources; };
  pkgs = import sources.nixpkgs { };
in with pkgs;
mkShell {
  buildInputs = [
    cacert
    curl
    git
    killall
    pkg-config
    rust
    unzip
    vault
    which
    pkgsStatic.openssl
    pkgsStatic.zlib
  ] ++ stdenv.lib.optionals stdenv.isDarwin
    [ darwin.apple_sdk.frameworks.Security ];
  RUST_BACKTRACE = 1;

  PKG_CONFIG_ALLOW_CROSS = true;
  PKG_CONFIG_ALL_STATIC = true;

  OPENSSL_DEV = pkgsStatic.openssl.dev;
  OPENSSL_STATIC = 1;
  OPENSSL_DIR = pkgsStatic.openssl.dev;
  OPENSSL_LIB_DIR = "${pkgsStatic.openssl.dev.out}/lib";
}
