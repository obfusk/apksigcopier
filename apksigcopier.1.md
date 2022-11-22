% apksigcopier(1) v1.1.0 | General Commands Manual
% FC Stegerman <flx@obfusk.net>
% 2022-11-21

# NAME

apksigcopier - copy/extract/patch android apk signatures & compare apks

# SYNOPSIS

**apksigcopier** copy \[*options*\] *signed_apk* *unsigned_apk* *output_apk*

**apksigcopier** extract \[*options*\] *signed_apk* *output_dir*

**apksigcopier** patch \[*options*\] *metadata_dir* *unsigned_apk* *output_apk*

**apksigcopier** compare \[*options*\] *first_apk* *second_apk*

**apksigcopier** \--version

**apksigcopier** \--help

**apksigcopier** \[*command*\] \--help

# DESCRIPTION

A command line tool for copying android APK signatures from a signed
APK to an unsigned one (in order to verify reproducible builds).  It
can also be used to compare two APKs with different signatures.

# COMMANDS

## copy

Copy (extract & patch) signatures from signed to unsigned APK.

## extract

Extract APK signatures from signed APK.

## patch

Patch extracted APK signatures onto unsigned APK.

## compare

Compare two APKs by copying the signature from the first to a copy of
the second and checking if the resulting APK verifies.

This command requires apksigner(1).

NB: copying from an APK v1-signed with signflinger to an APK signed with
apksigner works, whereas the reverse fails; see the FAQ in the README.

# OPTIONS

## copy/extract/patch

\--v1-only [no|auto|yes]

Whether to expect only a v1 signature: *no* means a v2 signature is
expected as well, *auto* means the presence of a v2 signature is
detected automatically, and *yes* means a v2 signature is not expected
(and ignored if it does exist).  Default: *no*.

You can also set the environment variable **APKSIGCOPIER_V1_ONLY**
instead.

## compare

\--unsigned

Accept unsigned *second_apk*.

\--min-sdk-version

Passed to apksigner(1) when verifying.

# ENVIRONMENT VARIABLES

The following environment variables can be set to *1*, *yes*, or
*true* to override the default behaviour.

## APKSIGCOPIER_EXCLUDE_ALL_META

Exclude all metadata files, not just MANIFEST.MF.

## APKSIGCOPIER_COPY_EXTRA_BYTES

Copy extra bytes after data (e.g. an existing v2 signature).

## APKSIGCOPIER_SKIP_REALIGNMENT

Skip realignment of ZIP entries.

# EXAMPLES

## extract

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

## patch

```bash
$ apksigcopier patch meta unsigned.apk out.apk
```

## copy

```bash
$ apksigcopier copy signed.apk unsigned.apk out.apk
```

## compare

```bash
$ apksigcopier compare foo-from-fdroid.apk foo-built-locally.apk
$ apksigcopier compare foo.apk --unsigned foo-unsigned.apk
```

# SEE ALSO

apksigner(1)

# COPYRIGHT

Copyright © 2022 FC Stegerman.  License GPLv3+: GNU GPL version 3 or
later <https://gnu.org/licenses/gpl.html>.  This is free software: you
are free to change and redistribute it.   There  is NO WARRANTY, to
the extent permitted by law.
