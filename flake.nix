{
  description = "AES_CPP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux"; # ou "aarch64-linux" selon ta machine
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "aes_cpp";
        version = "1.0";
        src = ./.;
        nativeBuildInputs = [ pkgs.cmake ];
        buildInputs = [ pkgs.gcc ];

        cmakeFlags = [ "-DCMAKE_BUILD_TYPE=Release" ];

        installPhase = ''
          mkdir -p $out/bin
          cp aes_cpp $out/bin/
        '';
      };
    };
}
