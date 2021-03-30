% apksigcopier(1) v0.3.0 | General Commands Manual
% Felix C. Stegerman <flx@obfusk.net>
% 2021-03-30

# NAME

apksigcopier - copy/extract/patch apk signatures

# SYNOPSIS

**apksigcopier** copy \[*options*\] *signed_apk* *unsigned_apk* *output_apk*

**apksigcopier** extract \[*options*\] *signed_apk* *output_dir*

**apksigcopier** patch \[*options*\] *metadata_dir* *unsigned_apk* *output_apk*

**apksigcopier** gen-dummy \[*options*\] *dummy_keystore*

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

## gen-dummy

Generate dummy key(store).

# OPTIONS

## copy, extract, patch

\--v1-only [no|auto|yes]

Whether to expect only a v1 signature: *no* means a v2 signature is
expected as well, *auto* means the presence of a v2 signature is
detected automatically, and *yes* means a v2 signature is not expected
(and ignored if it does exist).  Default: *no*.

## copy, extract

\--dummy-keystore *file*

To avoid the overhead of generating a new dummy keystore every time,
you can generate it once using **gen-dummy** and re-use it by passing
it to this option.

\--use-zip [no|auto|yes]

Whether to use the external zip(1) command to copy the metadata to the
output APK (after signing it with the dummy key): *no* means the
pure-Python implementation is used, *auto* means the external command
is used when it is available, and *yes* means the external command is
used (and its absence is considered an error).  Default: *no*.

The pure-Python implementation is less tested, but is the only
implementation that supports APKs generated using *zipflinger*.

## gen-dummy

\--keysize *integer*

Size of the dummy signing key to generate.  Default: 4096.

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
