<!-- {{{1

    File        : README.md
    Maintainer  : FC Stegerman <flx@obfusk.net>
    Date        : 2022-11-01

    Copyright   : Copyright (C) 2022  FC Stegerman
    Version     : v1.1.0
    License     : GPLv3+

}}}1 -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigcopier.svg?logo=github)](https://github.com/obfusk/apksigcopier/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![CI](https://github.com/obfusk/apksigcopier/workflows/CI/badge.svg)](https://github.com/obfusk/apksigcopier/actions?query=workflow%3ACI)
[![GPLv3+](https://img.shields.io/badge/license-GPLv3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

<a href="https://repology.org/project/apksigcopier/versions">
  <img src="https://repology.org/badge/vertical-allrepos/apksigcopier.svg?header="
    alt="Packaging status" align="right" />
</a>

<a href="https://repology.org/project/python:apksigcopier/versions">
  <img src="https://repology.org/badge/vertical-allrepos/python:apksigcopier.svg?header="
    alt="Packaging status" align="right" />
</a>

# apksigcopier

## copy/extract/patch android apk signatures & compare apks

`apksigcopier` is a tool for copying [android APK
signatures](https://source.android.com/docs/security/features/apksigning)
from a signed APK to an unsigned one (in order to verify [reproducible
builds](https://f-droid.org/docs/Reproducible_Builds/)).  It can also
be used to compare two APKs with different signatures.  Its
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

### Compare (Copy to temporary file & Verify)

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

### How does patching work?

First it copies the APK exactly like `apksigner` would when signing it,
including re-aligning ZIP entries and skipping existing v1 signature files.

Then it adds the extracted v1 signature files (`.SF`, `.RSA`/`.DSA`/`.EC`,
`MANIFEST.MF`) to the APK, using the correct ZIP metadata (either the same
metadata as `apksigner` would, or from `differences.json`).

And lastly it inserts the extracted APK Signing Block at the correct offset
(adding zero padding if needed) and updates the CD offset in the EOCD.

### What about APKs signed by gradle/zipflinger/signflinger instead of apksigner?

Compared to APKs signed by `apksigner`, APKs signed with a v1 signature by
`zipflinger`/`signflinger` (e.g. using `gradle`) have different ZIP metadata --
`create_system`, `create_version`, `external_attr`, `extract_version`,
`flag_bits` -- and `compresslevel` for the v1 signature files (`.SF`,
`.RSA`/`.DSA`/`.EC`, `MANIFEST.MF`); they also usually have a 132-byte virtual
entry at the start as well.

Recent versions of `apksigcopier` will detect these ZIP metadata differences and
the virtual entry (if any); `extract` will save them in a `differences.json`
file (if they exist), which `patch` will read (if it exists); `copy` and
`compare` simply pass the same information along internally.

### What are these virtual entries?

A virtual entry is a ZIP entry with an empty filename, an extra field filled
with zero bytes, and no corresponding central directory entry (so it should be
effectively invisible to most ZIP tools).

When `zipflinger` deletes an entry it leaves a "hole" in the archive when there
remain non-deleted entries after it.  It later fills these "holes" with virtual
entries.

There is usually a 132-byte virtual entry at the start of an APK signed with a
v1 signature by `signflinger`/`zipflinger`; almost certainly this is a default
manifest ZIP entry created at initialisation, deleted (from the central
directory but not from the file) during v1 signing, and eventually replaced by a
virtual entry.

Depending on what value of `Created-By` and `Built-By` were used for the default
manifest, this virtual entry may be a different size; `apksigcopier` supports
any size between 30 and 4096 bytes.

## Tab Completion

NB: the syntax for the environment variable changed in click >= 8.0,
use e.g. `source_bash` instead of `bash_source` for older versions.

For Bash, add this to `~/.bashrc`:

```bash
eval "$(_APKSIGCOPIER_COMPLETE=bash_source apksigcopier)"
```

For Zsh, add this to `~/.zshrc`:

```zsh
eval "$(_APKSIGCOPIER_COMPLETE=zsh_source apksigcopier)"
```

For Fish, add this to `~/.config/fish/completions/apksigcopier.fish`:

```fish
eval (env _APKSIGCOPIER_COMPLETE=fish_source apksigcopier)
```

## Installing

### Debian

Official packages are available in
[Debian](https://packages.debian.org/apksigcopier) and
[Ubuntu](https://packages.ubuntu.com/apksigcopier).

```bash
$ apt install apksigcopier
```

You can also manually build a Debian package using the `debian/sid`
branch, or download a pre-built `.deb` via GitHub releases.

### NixOS & Arch Linux

Official packages are also available in
[nixpkgs](https://search.nixos.org/packages?query=apksigcopier) and
[Arch Linux](https://archlinux.org/packages/community/any/apksigcopier/)
(and derivatives).

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

## Dependencies

* Python >= 3.7 + click.
* The `compare` command also requires `apksigner`.

### Debian/Ubuntu

```bash
$ apt install python3-click
$ apt install apksigner         # only needed for the compare command
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
