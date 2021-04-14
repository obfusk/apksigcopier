% apksigcopier(1) v0.4.0 | General Commands Manual
% Felix C. Stegerman <flx@obfusk.net>
% 2021-04-14

# NAME

apksigcopier - copy/extract/patch apk signatures

# SYNOPSIS

**apksigcopier** copy \[*options*\] *signed_apk* *unsigned_apk* *output_apk*

**apksigcopier** extract \[*options*\] *signed_apk* *output_dir*

**apksigcopier** patch \[*options*\] *metadata_dir* *unsigned_apk* *output_apk*

**apksigcopier** \--version

**apksigcopier** \--help

**apksigcopier** \[*command*\] \--help

# DESCRIPTION

A command line tool for copying APK signatures from a signed APK to an
unsigned one (in order to verify reproducible builds).

# COMMANDS

## copy

Copy (extract & patch) signatures from signed to unsigned APK.

## extract

Extract APK signatures from signed APK.

## patch

Patch extracted APK signatures onto unsigned APK.

# OPTIONS

\--v1-only [no|auto|yes]

Whether to expect only a v1 signature: *no* means a v2 signature is
expected as well, *auto* means the presence of a v2 signature is
detected automatically, and *yes* means a v2 signature is not expected
(and ignored if it does exist).  Default: *no*.

You can also set the environment variable **APKSIGCOPIER_V1_ONLY**
instead.

# ENVIRONMENT VARIABLES

The following environment variables can be set to *1*, *yes*, or
*true* to overide the default behaviour.

## APKSIGCOPIER_EXCLUDE_ALL_META

Exclude all metadata files, not just MANIFEST.MF.

## APKSIGCOPIER_COPY_EXTRA_BYTES

Copy extra bytes after data (e.g. an existing v2 signature).

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

# SEE ALSO

apksigner(1)

# COPYRIGHT

Copyright © 2021 Felix C. Stegerman.  License GPLv3+: GNU GPL version
3 or later <https://gnu.org/licenses/gpl.html>.  This is free software:
you are free to change and redistribute it.   There  is NO WARRANTY,
to the extent permitted by law.
