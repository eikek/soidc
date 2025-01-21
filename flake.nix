{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    devshell-tools.url = "github:eikek/devshell-tools";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    devshell-tools,
  }:
    {
      nixosConfigurations = let
        services = {
          services.dev-keycloak = {
            enable = true;
          };
          services.dev-authentik = {
            enable = true;
          };
        };
      in {
        soidcvm = devshell-tools.lib.mkVm {
          system = flake-utils.lib.system.x86_64-linux;
          modules = [
            services
            {
              virtualisation.memorySize = 2048;
              networking.hostName = "soidcvm";
            }
          ];
        };

        soidccnt = devshell-tools.lib.mkContainer {
          system = flake-utils.lib.system.x86_64-linux;
          modules = [
            services
            {
              networking.hostName = "soidccnt";
            }
          ];
        };
      };
    }
    // flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      ciPkgs = with pkgs; [
        devshell-tools.packages.${system}.sbt17
        jdk17
      ];
      devshellPkgs =
        ciPkgs
        ++ (with pkgs; [
          jq
          scala-cli
        ]);
    in {
      formatter = pkgs.alejandra;

      devShells = {
        default = pkgs.mkShellNoCC {
          buildInputs = (builtins.attrValues devshell-tools.legacyPackages.${system}.cnt-scripts) ++ devshellPkgs;
          DEV_CONTAINER = "soidccnt";
        };
        vm = pkgs.mkShellNoCC {
          buildInputs = (builtins.attrValues devshell-tools.legacyPackages.${system}.vm-scripts) ++ devshellPkgs;
          DEV_VM = "soidcvm";
        };
        ci = pkgs.mkShellNoCC {
          buildInputs = ciPkgs;
          SBT_OPTS = "-Xmx2G -Xss4m";
        };
      };
    });
}
