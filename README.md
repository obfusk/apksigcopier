<!-- {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2021-03-25

    Copyright   : Copyright (C) 2021  Felix C. Stegerman
    Version     : v0.0.2
    License     : GPLv3+

}}}1 -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigcopier.svg?logo=github)](https://github.com/obfusk/apksigcopier/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![CI](https://github.com/obfusk/apksigcopier/workflows/CI/badge.svg)](https://github.com/obfusk/apksigcopier/actions?query=workflow%3ACI)
[![GPLv3+](https://img.shields.io/badge/license-GPLv3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

## apksigcopier - copy/extract/patch apk signatures

Extract:

```bash
$ mkdir meta
$ apksigcopier extract signed.apk meta
$ ls -1 meta
DUMMY.RSA
DUMMY.RSA.json
DUMMY.SF
DUMMY.SF.json
MANIFEST.MF
MANIFEST.MF.json
sigblock
sigoffset
```

Patch:

```bash
$ apksigcopier patch meta unsigned.apk out.apk
```

Copy (Extract & Patch):

```bash
$ apksigcopier copy signed.apk unsigned.apk out.apk
```

## CAVEATS

Recent versions of the Android gradle plugin will use *zipflinger* --
which arranges the contents of the APK differently -- making
apksigcopier fail to work.  You can tell the plugin not to use
*zipflinger* by setting `android.useNewApkCreator=false` in
`gradle.properties`.

## Help

```bash
$ apksigcopier --help
```

## Tab Completion

For Bash, add this to `~/.bashrc`:

```bash
eval "$(_SHTST_COMPLETE=source_bash apksigcopier)"
```

For Zsh, add this to `~/.zshrc`:

```zsh
eval "$(_SHTST_COMPLETE=source_zsh apksigcopier)"
```

For Fish, add this to `~/.config/fish/completions/apksigcopier.fish`:

```fish
eval (env _SHTST_COMPLETE=source_fish apksigcopier)
```

## Requirements

* Python >= 3.7 + click + `apksigner` + `zip`.

### Debian/Ubuntu

```bash
$ apt install python3-click apksigner zip
```

## Installing

### Using pip

```bash
$ pip install apksigcopier
```

NB: depending on your system you may need to use e.g. `pip3 --user`
instead of just `pip`.

### From git

NB: this installs the latest development version, not the latest
release.

```bash
$ git clone https://github.com/obfusk/apksigcopier.git
$ cd apksigcopier
$ pip install -e .
```

NB: you may need to add e.g. `~/.local/bin` to your `$PATH` in order
to run `apksigcopier`.

To update to the latest development version:

```bash
$ cd apksigcopier
$ git pull --rebase
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
