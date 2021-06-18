<!-- {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2021-06-18

    Copyright   : Copyright (C) 2021  Felix C. Stegerman
    Version     : v1.0.0
    License     : GPLv3+

}}}1 -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigcopier.svg?logo=github)](https://github.com/obfusk/apksigcopier/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![CI](https://github.com/obfusk/apksigcopier/workflows/CI/badge.svg)](https://github.com/obfusk/apksigcopier/actions?query=workflow%3ACI)
[![GPLv3+](https://img.shields.io/badge/license-GPLv3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

## apksigcopier - copy/extract/patch apk signatures & compare apks

`apksigcopier` is a tool for copying APK signatures from a signed APK
to an unsigned one (in order to verify reproducible builds).  It can
also be used to compare two APKs with different signatures.  Its
command-line tool offers four operations:

* copy signatures directly from a signed to an unsigned APK
* extract signatures from a signed APK to a directory
* patch previously extracted signatures onto an unsigned APK
* compare two APKs with different signatures

### Extract

```bash
$ mkdir meta
$ apksigcopier extract signed.apk meta
$ ls -1 meta
8BEA2A77.RSA
8BEA2A77.SF
APKSigningBlock
APKSigningBlockOffset
MANIFEST.MF
```

### Patch

```bash
$ apksigcopier patch meta unsigned.apk out.apk
```

### Copy (Extract & Patch)

```bash
$ apksigcopier copy signed.apk unsigned.apk out.apk
```

### Compare

This command requires `apksigner`.

```bash
$ apksigcopier compare foo-from-fdroid.apk foo-built-locally.apk
$ apksigcopier compare --unsigned foo.apk foo-unsigned.apk
```

### Help

```bash
$ apksigcopier --help
$ apksigcopier copy --help      # extract --help, patch --help, etc.

$ man apksigcopier              # requires the man page to be installed
```

### Environment Variables

The following environment variables can be set to `1`, `yes`, or
`true` to override the default behaviour:

* set `APKSIGCOPIER_EXCLUDE_ALL_META=1` to exclude all metadata files
* set `APKSIGCOPIER_COPY_EXTRA_BYTES=1` to copy extra bytes after data (e.g. a v2 sig)

## Python API

```python
>>> from apksigcopier import do_extract, do_patch, do_copy, do_compare
>>> do_extract(signed_apk, output_dir, v1_only=NO)
>>> do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO)
>>> do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO)
>>> do_compare(first_apk, second_apk, unsigned=False)
```

You can use `False`, `None`, and `True` instead of `NO`, `AUTO`, and
`YES` respectively.

The following global variables (which default to `False`), can be set
to override the default behaviour:

* set `exclude_all_meta=True` to exclude all metadata files
* set `copy_extra_bytes=True` to copy extra bytes after data (e.g. a v2 sig)

## FAQ

### What kind of signatures does apksigcopier support?

It currently supports v1 + v2 + v3 (which is a variant of v2).

It should also support v4, since these are stored in a separate file
(and require a complementary v2/v3 signature).

When using the `extract` command, the v2/v3 signature is saved as
`APKSigningBlock` + `APKSigningBlockOffset`.

## Tab Completion

For Bash, add this to `~/.bashrc`:

```bash
eval "$(_APKSIGCOPIER_COMPLETE=source_bash apksigcopier)"
```

For Zsh, add this to `~/.zshrc`:

```zsh
eval "$(_APKSIGCOPIER_COMPLETE=source_zsh apksigcopier)"
```

For Fish, add this to `~/.config/fish/completions/apksigcopier.fish`:

```fish
eval (env _APKSIGCOPIER_COMPLETE=source_fish apksigcopier)
```

## Requirements

* Python >= 3.5 + click.
* The `compare` command also requires `apksigner`.

### Debian/Ubuntu

```bash
$ apt install python3-click
$ apt install apksigner         # only needed for the compare command
```

## Installing

### Debian

An official Debian package should be available soon.  You can also
manually build one using the `debian/sid` branch, or download a
pre-built `.deb` via GitHub releases.

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
