<!-- SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigcopier.svg?logo=github)](https://github.com/obfusk/apksigcopier/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigcopier.svg)](https://pypi.python.org/pypi/apksigcopier)
[![CI](https://github.com/obfusk/apksigcopier/actions/workflows/ci.yml/badge.svg)](https://github.com/obfusk/apksigcopier/actions/workflows/ci.yml)
[![CI (more)](https://github.com/obfusk/apksigcopier/actions/workflows/ci-more.yml/badge.svg)](https://github.com/obfusk/apksigcopier/actions/workflows/ci-more.yml)
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

`apksigcopier` is a tool that enables using an [android APK
signature](https://source.android.com/docs/security/features/apksigning) as a
[build input](https://reproducible-builds.org/docs/embedded-signatures/) (by
copying it from a signed APK to an unsigned one), making it possible to create a
([bit-by-bit identical](https://reproducible-builds.org/docs/definition/))
[reproducible build](https://reproducible-builds.org/) from the source code
without having access to the private key used to create the signature.  It can
also be used to verify that two APKs with different signatures are otherwise
identical.  Its command-line tool offers four operations:

* copy signatures directly from a signed to an unsigned APK
* extract signatures from a signed APK to a directory
* patch previously extracted signatures onto an unsigned APK
* compare two APKs with different signatures

NB: `apksigcopier` tries to validate the data it processes to some extent, but
is fundamentally a tool to *copy* signature data only; it should never copy any
data that cannot be part of a signature but it cannot validate APKs or ensure
the signature data does not contain any kind of payload as data can often be
added to signatures without invalidating them and part of the signature data may
not be verified under certain conditions (e.g. v1 signature data may not be
verified at all depending on minimum/target SDK version etc.).

### Extract

```bash
$ mkdir meta
$ apksigcopier extract signed.apk meta
$ ls -1 meta
APKSigningBlock
APKSigningBlockOffset
v1signature.zip
```

### Patch

```bash
$ apksigcopier patch meta unsigned.apk out.apk
```

### Copy (Extract & Patch)

```bash
$ apksigcopier copy signed.apk unsigned.apk out.apk
```

### Compare (Copy & Verify)

Compare two APKs by copying the signature from the first to a copy of the second
and checking if the resulting APK verifies.  Also checks if the SHA-256 hash of
the resulting APK is identical to that of the original (only warns when
`--no-check-sha256` is used).

This command requires `apksigner` (unless `--no-check-signature` is used).

```bash
$ apksigcopier compare foo-from-fdroid.apk foo-built-locally.apk
$ apksigcopier compare --unsigned foo.apk foo-unsigned.apk
```

NB: copying from an APK v1-signed with `signflinger` to an APK signed with
`apksigner` works, whereas the reverse fails; see the [FAQ](#faq).

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
* set `APKSIGCOPIER_SKIP_REALIGNMENT=1` to skip realignment of ZIP entries
* set `APKSIGCOPIER_LEGACY_V1SIGFILE=1` to use the legacy v1 signature files format

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
* set `skip_realignment=True` to skip realignment of ZIP entries
* set `legacy_v1sigfile=True` to use the legacy v1 signature files format

## FAQ

### What is the purpose of this tool?

This is a tool for [*reproducible builds*](https://reproducible-builds.org/)
only.  Its purpose is to allow verifying that *different builds* from the same
source code produce identical results, to prove that two APKs -- one built and
signed by the upstream developer, another one built by you (or some trusted
third party) from the published source code -- are *identical*.  Since you
cannot create an identical signature without the private key, you need to copy
it (and nothing else) as part of the build process instead to be able to create
a bit-by-bit identical APK.

> The motivation behind the Reproducible Builds project is [...] to allow
> verification that no vulnerabilities or backdoors have been introduced during
> this compilation process. By promising identical results are always generated
> from a given source, this allows multiple third parties to come to a consensus
> on a “correct” result, highlighting any deviations as suspect and worthy of
> scrutiny.

#### Modified APKs

Copying a signature to a modified APK will not work (i.e. it cannot possibly be
valid even if the copying itself seems to work) and this is not a tool for doing
anything of the sort.

Copying a signature will succeed even if the signature is not valid for the
target APK -- as long as the target APK is unsigned and not larger than the
source APK it can be inserted successfully.  But a signature that is not valid
for the target APK will never verify.

### What kind of signatures does apksigcopier support?

It currently supports v1 + v2 + v3 (which is a variant of v2).

It should also support v4, since these are stored in a separate file
(and require a complementary v2/v3 signature).

When using the `extract` command, the v2/v3 signature is saved as
`APKSigningBlock` + `APKSigningBlockOffset`; the v1 signature is currently saved
as `v1signature.zip` to preserve all the ZIP metadata; the legacy v1 signature
files format (still supported for patching and available with `--legacy` for
extracting and copying) extracted the v1 signature files individually instead.

### How does patching work?

First it copies the APK exactly like `apksigner` would when signing it,
including re-aligning ZIP entries and skipping existing v1 signature files.

Then it adds the v1 signature files (`.SF`, `.RSA`/`.DSA`/`.EC`, `MANIFEST.MF`)
to the APK, using the correct ZIP metadata (when using the legacy v1 signature
files format that does not preserve the ZIP metadata directly, either the same
metadata as `apksigner` would, or from `differences.json`).

And lastly it inserts the extracted APK Signing Block at the correct offset
(adding zero padding if needed) and updates the central directory (CD) offset in
the end of central directory (EOCD) record.

For more information about the ZIP file format, see e.g. [the Wikipedia
article](https://en.wikipedia.org/wiki/ZIP_%28file_format%29).

### What does the "APK Signing Block offset < central directory offset" error mean?

It means that `apksigcopier` can't insert the APK Signing Block at the required
location, since that offset is in the middle of the ZIP data (instead of right
after the data, before the central directory).

In other words: the APK you are trying to copy the signature to is larger than
the one the signature was copied from.  Thus the signature cannot be copied (and
could never have been valid for the APK you are trying to copy it to).

In the context of verifying [reproducible builds](https://reproducible-builds.org),
getting this error almost certainly means the build was not reproducible.

### What does the "Unexpected metadata" error mean?

It almost always means the target APK was signed; you can only copy a signature
to an unsigned APK.

### What about signatures made by apksigner from build-tools >= 35.0.0-rc1?

Since `build-tools` >= 35.0.0-rc1, [backwards-incompatible changes to
`apksigner`](https://issuetracker.google.com/issues/351408623) break
`apksigcopier` as it now by default forcibly replaces existing alignment padding
and changed the default page alignment from 4k to 16k (same as Android Gradle
Plugin >= 8.3, so the latter is only an issue when using older AGP).

Unlike `zipalign` and Android Gradle Plugin, which use zero padding, `apksigner`
uses a `0xd935` "Android ZIP Alignment Extra Field" which stores the alignment
itself plus zero padding and is thus always at least 6 bytes.

It now forcibly replaces existing padding even when the file is already aligned
as it should be, except when `--alignment-preserved` is specified, in which case
it will keep existing (non)alignment and padding.

This means it will replace existing zero padding with different padding for each
and every non-compressed file.  This padding will not only be different but also
longer for regular files aligned to 4 bytes with zero padding, but often the
same size for `.so` shared objects aligned to 16k (unless they happened to
require less than 6 bytes of zero padding before).

Unfortunately, supporting this change in `apksigcopier` without breaking
compatibility with the signatures currently supported would require rather
significant changes.  Luckily, there are 3 workarounds available:

First: use `apksigner` from `build-tools` <= 34.0.0 (clearly not ideal).

Second: use `apksigner sign` from `build-tools` >= 35.0.0-rc1 with the
`--alignment-preserved` option.

Third: use [`zipalign.py --page-size 16 --pad-like-apksigner
--replace`](https://github.com/obfusk/reproducible-apk-tools#zipalignpy) on the
unsigned APK to replace the padding the same way `apksigner` now does before
using `apksigcopier`.

### What about APKs signed by gradle/zipflinger/signflinger instead of apksigner?

Compared to APKs signed by `apksigner`, APKs signed with a v1 signature by
`zipflinger`/`signflinger` (e.g. using `gradle`) have different ZIP metadata --
`create_system`, `create_version`, `external_attr`, `extract_version`,
`flag_bits` -- and `compresslevel` for the v1 signature files (`.SF`,
`.RSA`/`.DSA`/`.EC`, `MANIFEST.MF`); they also used to have a 132-byte virtual
entry at the start (before this [was fixed in AGP
8.1](https://issuetracker.google.com/issues/268071371)).

Recent versions of `apksigcopier` will handle these differences and the virtual
entry (if any) as the `v1signature.zip` saved by `extract` simply preserves all
the ZIP metadata; the legacy v1 signature files format saves differing metadata
in a `differences.json` file, which `patch` will read (if it exists); `copy` and
`compare` simply pass the same information along internally.

#### CAVEAT for compare

NB: because `compare` copies from the first APK to the second, it will fail when
only the second APK is v1-signed with `zipflinger`/`signflinger`; e.g.

```bash
$ compare foo-signflinger.apk foo-apksigner.apk   # copies virtual entry; works
$ compare foo-apksigner.apk foo-signflinger.apk   # only 2nd APK has virtual entry
DOES NOT VERIFY
[...]
Error: failed to verify /tmp/.../output.apk.
```

### What are these virtual entries?

A virtual entry is a ZIP entry with an empty filename, an extra field filled
with zero bytes, and no corresponding central directory entry (so it should be
effectively invisible to most ZIP tools).

When `zipflinger` deletes an entry it leaves a "hole" in the archive when there
remain non-deleted entries after it.  It later fills these "holes" with virtual
entries.

Before Android Gradle Plugin 8.1 (see the section on `gradle` above) there used
to be a 132-byte virtual entry at the start of an APK signed with a v1 signature
by `signflinger`/`zipflinger`; this is a default manifest ZIP entry created at
initialisation, deleted (from the central directory but not from the file)
during v1 signing, and eventually replaced by a virtual entry.

Depending on what value of `Created-By` and `Built-By` were used for the default
manifest, this virtual entry may be a different size; `apksigcopier` supports
any size between 30 and 4096 bytes.

<!--
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
-->

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

* Python >= 3.8 + click.
* The `compare` command also requires `apksigner`.

### Debian/Ubuntu

```bash
$ apt install python3-click
$ apt install apksigner         # only needed for the compare command
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
