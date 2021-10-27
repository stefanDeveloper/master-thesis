{
  tinypkgs ? import (fetchTarball https://gitlab.inria.fr/nix-tutorial/packages-repository/-/archive/master/packages-repository-master.tar.gz) {}
}:

with tinypkgs; # Put tinypkgs's attributes in the current scope.
with pkgs; # Same for pkgs.

mkShell {
  buildInputs = [
    chord

    # Defines a python + set of packages.
    (python3.withPackages (ps: with ps; with python3Packages; [
      jupyter
      ipython
      geopandas
      pycountry

      # Uncomment the following lines to make them available in the shell.
      pandas
      numpy
      matplotlib
    ]))
  ];

  # Automatically run jupyter when entering the shell.
  shellHook = "jupyter notebook";
}
