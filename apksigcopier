#!/usr/bin/python3
# encoding: utf-8

# --                                                            ; {{{1
#
# File        : apksigcopier
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2021-03-25
#
# Copyright   : Copyright (C) 2021  Felix C. Stegerman
# Version     : v0.0.2
# License     : GPLv3+
#
# --                                                            ; }}}1

"""
copy/extract/patch apk signatures
"""

import glob
import json
import os
import shutil
import subprocess
import tempfile
import zipfile

from collections import namedtuple

import click

__version__ = "0.0.2"
name = "apksigcopier"

ZipData = namedtuple("ZipData", "cd_offset eocd_offset cd_and_eocd".split())


# FIXME
class ZeroedZipInfo(zipfile.ZipInfo):
    def __init__(self, zinfo):
        for k in self.__slots__:
            setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name):
        if name == "date_time":
            return (1980, 0, 0, 0, 0, 0)
        if name == "external_attr":
            return 0
        if name == "flag_bits":
            return 0x800
        return object.__getattribute__(self, name)


def is_meta(filename):
    return filename.startswith("META-INF") and \
        any(filename.endswith(ext) for ext in ".SF .RSA .MF".split())


def gen_dummy_key(keystore, size=4096):
    args = f"""
        keytool -genkey -v -alias dummy -keyalg RSA -keysize {size}
            -sigalg SHA512withRSA -validity 10000
            -keystore {keystore} -storepass dummy-password
            -dname CN=dummy
    """.split()
    subprocess.run(args, check=True)


def sign_with_dummy_key(out, keystore):
    args = f"""
        apksigner sign -v --ks {keystore} --ks-key-alias dummy
            --ks-pass pass:dummy-password
    """.split() + [out]
    subprocess.run(args, check=True)


def extract_meta(signed):
    """Extract v1 signature metadata files from signed APK."""
    with zipfile.ZipFile(signed, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def replace_meta(extracted_meta, out):
    """Replace v1 signature metadata in signed APK (removes v2 sig block)."""
    with zipfile.ZipFile(out, "r") as zf_out:
        meta = [info.filename for info in zf_out.infolist()
                if is_meta(info.filename)]
        subprocess.run(["zip", "-d", out] + meta, check=True)
    with zipfile.ZipFile(out, "a") as zf_out:
        for info, data in extracted_meta:
            zf_out.writestr(ZeroedZipInfo(info), data, compresslevel=9)


# https://source.android.com/security/apksigning/v2#apk-signing-block-format
# https://en.wikipedia.org/wiki/ZIP_(file_format)#End_of_central_directory_record_(EOCD)
#
# =================================
# | Contents of ZIP entries       |
# =================================
# | APK Signing Block             |
# | ----------------------------- |
# | | size (w/o this) uint64 LE | |
# | | ...                       | |
# | | size (again)    uint64 LE | |
# | | "APK Sig Block 42" (16B)  | |
# | ----------------------------- |
# =================================
# | ZIP Central Directory         |
# =================================
# | ZIP End of Central Directory  |
# | ----------------------------- |
# | | 0x06054b50 ( 4B)          | |
# | | ...        (12B)          | |
# | | CD Offset  ( 4B)          | |
# | | ...                       | |
# | ----------------------------- |
# =================================


# FIXME: optimise?!
def extract_v2_sig(apkfile, count=1024**2):
    """Extract APK Signing Block from APK."""
    with open(apkfile, "rb") as fh:
        fh.seek(-count, os.SEEK_END)
        data = fh.read()
        fh.seek(data.rindex(b"APK Sig Block 4") - len(data) - 8, os.SEEK_CUR)
        sb_size2 = int.from_bytes(fh.read(8), "little")
        fh.seek(-sb_size2 + 8, os.SEEK_CUR)
        sb_size1 = int.from_bytes(fh.read(8), "little")
        assert sb_size1 == sb_size2
        fh.seek(-8, os.SEEK_CUR)
        sb_offset = fh.tell()
        sig_block = fh.read(sb_size2 + 8)
    return sb_offset, sig_block


def zip_data(apkfile, count=1024):
    """Extract central directory & EOCD from ZIP."""
    with open(apkfile, "rb") as fh:
        fh.seek(-count, os.SEEK_END)
        data = fh.read()
        fh.seek(data.rindex(b"\x50\x4b\x05\x06") - len(data), os.SEEK_CUR)
        eocd_offset = fh.tell()
        fh.seek(16, os.SEEK_CUR)
        cd_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(cd_offset)
        cd_and_eocd = fh.read()
    return ZipData(cd_offset, eocd_offset, cd_and_eocd)


def patch_v2_sig(extracted_v2_sig, out):
    """Implant extracted v2/v3 signature into APK."""
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(out)
    padding = b"\x00" * (signed_sb_offset - data_out.cd_offset)
    offset = len(signed_sb) + len(padding)
    with open(out, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


@click.group(help="""
    apksigcopier - copy/extract/patch apk signatures
""")
@click.version_option(__version__)
@click.pass_context
def cli(ctx):
    pass


@cli.command(help="""
    Extract APK signatures from signed APK.
""")
@click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
@click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
def extract(signed_apk, output_dir):
    extracted_meta = extract_meta(signed_apk)
    for info, data in extracted_meta:
        name = os.path.basename(info.filename)
        with open(os.path.join(output_dir, f"{name}.json"), "w") as fh:
            info_ = {k: getattr(info, k) for k in info.__slots__}
            del info_["comment"], info_["extra"]               # FIXME
            json.dump(info_, fh)
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(data)
    signed_sb_offset, signed_sb = extract_v2_sig(signed_apk)
    with open(os.path.join(output_dir, "sigoffset"), "w") as fh:
        fh.write(f"{signed_sb_offset}\n")
    with open(os.path.join(output_dir, "sigblock"), "wb") as fh:
        fh.write(signed_sb)


@cli.command(help="""
    Patch extracted APK signatures into unsigned APK.
""")
@click.option("--dummy-keystore", type=click.Path(exists=True, dir_okay=False))
@click.argument("meta_dir", type=click.Path(exists=True, file_okay=False))
@click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
@click.argument("output_apk", type=click.Path(dir_okay=False))
def patch(meta_dir, unsigned_apk, output_apk, dummy_keystore):
    extracted_meta = []
    for what in "SF RSA MF".split():
        filename, = glob.glob(os.path.join(meta_dir, f"*.{what}"))
        with open(f"{filename}.json", "rb") as fh:
            info_ = json.load(fh)
            info = zipfile.ZipInfo()
            for k in info.__slots__:
                if k in info_:
                    setattr(info, k, info_[k])
            info.date_time = tuple(info.date_time)
            info.comment = info.extra = b""                    # FIXME
        with open(filename, "rb") as fh:
            data = fh.read()
        extracted_meta.append((info, data))
    with open(os.path.join(meta_dir, "sigoffset"), "r") as fh:
        signed_sb_offset = int(fh.read())
    with open(os.path.join(meta_dir, "sigblock"), "rb") as fh:
        signed_sb = fh.read()
    extracted_v2_sig = signed_sb_offset, signed_sb
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              dummy_keystore)


@cli.command(help="""
    Copy (extract & patch) signatures from signed to unsigned APK.
""")
@click.option("--dummy-keystore", type=click.Path(exists=True, dir_okay=False))
@click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
@click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
@click.argument("output_apk", type=click.Path(dir_okay=False))
def copy(signed_apk, unsigned_apk, output_apk, dummy_keystore):
    extracted_meta = extract_meta(signed_apk)
    extracted_v2_sig = extract_v2_sig(signed_apk)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              dummy_keystore)


@cli.command(help="""
    Generate dummy key (store).
""")
@click.option("--keysize", type=int, default=4096, show_default=True)
@click.argument("dummy_keystore", type=click.Path(dir_okay=False))
def gen_dummy(dummy_keystore, keysize):
    gen_dummy_key(dummy_keystore, keysize)


def patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk,
              output_apk, dummyks=None):
    def f():
        shutil.copy(unsigned_apk, output_apk)
        sign_with_dummy_key(output_apk, dummyks)
        replace_meta(extracted_meta, output_apk)
        patch_v2_sig(extracted_v2_sig, output_apk)
    if dummyks is None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dummyks = os.path.join(tmpdir, "dummy-keystore")
            gen_dummy_key(dummyks)
            f()
    else:
        f()


do_extract = extract.callback
do_patch = patch.callback
do_copy = copy.callback


def main():
    cli(prog_name=name)


if __name__ == "__main__":
    main()

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
