{ sources ? import ./sources.nix }:

let
  pkgs =
    import sources.nixpkgs { overlays = [ (import sources.nixpkgs-mozilla) ]; };
  channel = "nightly";
  date = "2020-08-29";
  targets = [ "x86_64-unknown-linux-musl" ];
  chan = pkgs.rustChannelOfTargets channel date targets;
in chan
