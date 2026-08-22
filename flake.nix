{
  description = "Clusterflux development and verification environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          publicPackages = import ./packages.nix { inherit pkgs self; };
          privatePackages =
            if builtins.pathExists ./web/packages.nix then
              import ./web/packages.nix { inherit pkgs self; }
            else
              { };
        in
        publicPackages // privatePackages);

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          cargoDeny = assert pkgs.cargo-deny.version == "0.18.9"; pkgs.cargo-deny;
          cargoMachete = assert pkgs.cargo-machete.version == "0.9.1"; pkgs.cargo-machete;
        in
        {
          dependency-policy-tools = pkgs.runCommand "clusterflux-dependency-policy-tools" {
            nativeBuildInputs = [ cargoDeny cargoMachete ];
          } ''
            test "$(cargo-deny --version)" = "cargo-deny 0.18.9"
            test "$(cargo-machete --version)" = "0.9.1"
            mkdir -p "$out"
          '';
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              (assert cargo-deny.version == "0.18.9"; cargo-deny)
              (assert cargo-machete.version == "0.9.1"; cargo-machete)
              clippy
              git
              jq
              nodejs_22
              podman
              rustc
              rustfmt
              zip
            ];
            shellHook = ''
              echo "Clusterflux shell: $(rustc --version), $(node --version), $(podman --version)"
            '';
          };
        });
    };
}
