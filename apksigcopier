#!/usr/bin/python3
# encoding: utf-8

# --                                                            ; {{{1
#
# File        : apksigcopier
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2021-03-30
#
# Copyright   : Copyright (C) 2021  Felix C. Stegerman
# Version     : v0.3.0
# License     : GPLv3+
#
# --                                                            ; }}}1

"""
copy/extract/patch apk signatures
"""

import glob
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib

from collections import namedtuple

__version__ = "0.3.0"
name = "apksigcopier"

SIGBLOCK, SIGOFFSET = "APKSigningBlock", "APKSigningBlockOffset"
APKSIGNER_CMD, KEYTOOL_CMD, ZIP_CMD = "apksigner keytool zip".split()
NOAUTOYES = NO, AUTO, YES = "no auto yes".split()
APK_META = re.compile(r"^META-INF/[0-9A-Za-z_-]+\.(SF|RSA|MF)$")
DATETIMEZERO = (1980, 0, 0, 0, 0, 0)

ZipData = namedtuple("ZipData", "cd_offset eocd_offset cd_and_eocd".split())


class APKSigningBlockError(Exception):
    pass


class NoAPKSigningBlock(APKSigningBlockError):
    pass


class ZipError(Exception):
    pass


# FIXME
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _override = {}

    def __init__(self, zinfo, **override):
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name):
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


class APKZipInfo(ReproducibleZipInfo):
    """Reproducible ZipInfo for APK files."""

    _override = dict(
        compress_type=8,
        create_system=0,
        create_version=20,
        date_time=DATETIMEZERO,
        external_attr=0,
        extract_version=20,
        flag_bits=0x800,
    )


# FIXME: .DSA?
def is_meta(filename):
    """Returns whether filename is an APK signature file."""
    return APK_META.fullmatch(filename) is not None


def noautoyes(value):
    """Turns False into NO, None into AUTO, and True into YES."""
    if isinstance(value, str):
        if value not in NOAUTOYES:
            raise ValueError("expected NO, AUTO, or YES")
        return value
    return {False: NO, None: AUTO, True: YES}[value]


# FIXME
def remove_from_zip(zipfile, meta, zip_cmd=None):
    """Remove signature files appended by apksigner from zip file."""
    if zip_cmd and shutil.which(zip_cmd):
        files = [info.filename for info in meta]
        subprocess.run([zip_cmd, "-q", "-d", zipfile] + list(files), check=True)
        return
    meta_cd_len = sum(46 + len(info.filename) for info in meta)
    meta_offset = min(info.header_offset for info in meta)
    data = zip_data(zipfile)
    cd_delta = data.cd_offset - meta_offset
    eocd_offset = data.eocd_offset - cd_delta - meta_cd_len
    with open(zipfile, "r+b") as fh:
        fh.seek(meta_offset)
        fh.truncate()
        fh.write(data.cd_and_eocd)
        fh.seek(eocd_offset)
        fh.truncate()
        fh.write(data.cd_and_eocd[data.eocd_offset - data.cd_offset:])
        fh.seek(eocd_offset + 8)
        cd_disk, cd_tot, cd_size, cd_off = struct.unpack("<HHLL", fh.read(12))
        fh.seek(-12, os.SEEK_CUR)
        fh.write(struct.pack("<HHLL", cd_disk - len(meta), cd_tot - len(meta),
                             cd_size - meta_cd_len, cd_off - cd_delta))


def gen_dummy_key(keystore, alias="dummy", keyalg="RSA", keysize=4096,
                  sigalg="SHA512withRSA", validity=10000,
                  storepass="dummy-password", dname="CN=dummy",
                  keytool_cmd=KEYTOOL_CMD):
    """Generate a dummy key using keytool."""
    args = [
        keytool_cmd, "-genkey", "-keystore", keystore, "-alias", alias,
        "-keyalg", keyalg, "-keysize", str(keysize), "-sigalg", sigalg,
        "-validity", str(validity), "-storepass", storepass, "-dname", dname
    ]
    subprocess.run(args, check=True)


def sign_with_dummy_key(output_apk, keystore, alias="dummy",
                        ks_pass="pass:dummy-password",
                        apksigner_cmd=APKSIGNER_CMD):
    """Sign APK with dummy key using apksigner."""
    args = [
        apksigner_cmd, "sign", "--ks", keystore, "--ks-key-alias", alias,
        "--ks-pass", ks_pass, output_apk
    ]
    subprocess.run(args, check=True)


def copy_zipfile(unsigned_apk, output_apk, exclude=is_meta):
    """Copy zip file (without signature files)."""
    with zipfile.ZipFile(unsigned_apk, "r") as zfi:
        with zipfile.ZipFile(output_apk, "w") as zfo:
            for info in zfi.infolist():
                if not exclude(info.filename):
                    zfo.writestr(info, zfi.read(info.filename))


# FIXME
def copy_apk(unsigned_apk, output_apk):
    """Copy APK (without MANIFEST.MF); returns max date_time."""
    exclude = ["META-INF/MANIFEST.MF"]
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
    date_time = max(info.date_time for info in infos)
    if not any(info.filename in exclude for info in infos):
        shutil.copy(unsigned_apk, output_apk)
        return date_time
    zdata = zip_data(unsigned_apk)
    offsets = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        for info in sorted(infos, key=lambda info: info.header_offset):
            off_i = fhi.tell()
            if info.header_offset > off_i:
                fho.write(fhi.read(info.header_offset - off_i))
            hdr = fhi.read(30)
            if hdr[:4] != b"\x50\x4b\x03\x04":
                raise ZipError("Expected local file header signature")
            n, m = struct.unpack("<HH", hdr[26:30])
            hdr += fhi.read(n + m)
            if info.filename in exclude:
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                off_o = fho.tell()
                if info.compress_type == 0:
                    old_off = info.header_offset + 30 + n + m
                    new_off = off_o + 30 + n
                    align = 4096 if info.filename.endswith(".so") else 4
                    if len(info.extra) >= 6 and info.extra[:2] == b"\x35\xd9":
                        dsize = int.from_bytes(info.extra[2:4], "little")
                        if dsize > 1 and dsize <= len(info.extra) - 4:
                            align = int.from_bytes(info.extra[4:6], "little")
                    if old_off % align == 0 and new_off % align != 0:
                        pad = (align - (new_off + 6) % align) % align
                        xtr = struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
                        m_b = int.to_bytes(len(xtr), 2, "little")
                        hdr = hdr[:28] + m_b + hdr[30:30 + n] + xtr
                offsets[id(info)] = off_o
                fho.write(hdr)
                size = info.compress_size
                while size > 0:
                    data = fhi.read(min(size, 4096))
                    size -= len(data)
                    fho.write(data)
        size = zdata.cd_offset - fhi.tell()
        while size > 0:
            data = fhi.read(min(size, 4096))
            size -= len(data)
            fho.write(data)
        cd_offset = fho.tell()
        for info in infos:
            hdr = fhi.read(46)
            if hdr[:4] != b"\x50\x4b\x01\x02":
                raise ZipError("Expected CD file header signature")
            n, m, k = struct.unpack("<HHH", hdr[28:34])
            hdr += fhi.read(n + m + k)
            if info.filename not in exclude:
                off = int.to_bytes(offsets[id(info)], 4, "little")
                hdr = hdr[:42] + off + hdr[46:]
                fho.write(hdr)
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return date_time


def extract_meta(signed_apk):
    """Extract v1 signature metadata files from signed APK."""
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def replace_meta(extracted_meta, output_apk, zip_cmd=None, date_time=DATETIMEZERO):
    """Replace v1 signature metadata in signed APK; removes v2 sig block."""
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        meta = [info for info in zf_out.infolist() if is_meta(info.filename)]
        if meta:
            date_time = meta[0].date_time                      # FIXME
            remove_from_zip(output_apk, meta, zip_cmd=zip_cmd)
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        info_data = [(APKZipInfo(info, date_time=date_time), data)
                     for info, data in extracted_meta]
        _write_to_zip(info_data, zf_out)


if "compresslevel" in zipfile.ZipFile.__doc__:                 # FIXME
    def _write_to_zip(info_data, zf_out):
        for info, data in info_data:
            zf_out.writestr(info, data, compresslevel=9)
else:
    def _write_to_zip(info_data, zf_out):
        old = zipfile._get_compressor
        zipfile._get_compressor = lambda _: zlib.compressobj(9, 8, -15)
        try:
            for info, data in info_data:
                zf_out.writestr(info, data)
        finally:
            zipfile._get_compressor = old


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


def extract_v2_sig(apkfile, expected=True):
    """Extract APK Signing Block from APK."""
    cd_offset = zip_data(apkfile).cd_offset
    with open(apkfile, "rb") as fh:
        fh.seek(cd_offset - 16)
        if fh.read(16) != b"APK Sig Block 42":
            if expected:
                raise NoAPKSigningBlock("No APK Sig Block")
            return None
        fh.seek(-24, os.SEEK_CUR)
        sb_size2 = int.from_bytes(fh.read(8), "little")
        fh.seek(-sb_size2 + 8, os.SEEK_CUR)
        sb_size1 = int.from_bytes(fh.read(8), "little")
        if sb_size1 != sb_size2:
            raise APKSigningBlockError("APK Sig Block sizes not equal")
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


def patch_v2_sig(extracted_v2_sig, output_apk):
    """Implant extracted v2/v3 signature into APK."""
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(output_apk)
    padding = b"\x00" * (signed_sb_offset - data_out.cd_offset)
    offset = len(signed_sb) + len(padding)
    with open(output_apk, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


def patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk,
              output_apk, dummyks=None, config={}):
    """Patch extracted_meta + extracted_v2_sig onto unsigned_apk and save as output_apk."""
    apksigner_cmd = config.get("apksigner_cmd", APKSIGNER_CMD)
    keytool_cmd = config.get("keytool_cmd", KEYTOOL_CMD)
    zip_cmd = config.get("zip_cmd", None)
    date_time = DATETIMEZERO
    if not (apksigner_cmd and shutil.which(apksigner_cmd)):
        logger = logging.getLogger(__name__)
        if extracted_v2_sig is None:
            logger.warning("Patching without apksigner (v1)")
            copy_zipfile(unsigned_apk, output_apk)
        else:
            logger.warning("Patching without apksigner (v2)")
            date_time = copy_apk(unsigned_apk, output_apk)
    else:
        shutil.copy(unsigned_apk, output_apk)
        if dummyks is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                dummyks = os.path.join(tmpdir, "dummy-keystore")
                gen_dummy_key(dummyks, keytool_cmd=keytool_cmd)
                sign_with_dummy_key(output_apk, dummyks, apksigner_cmd=apksigner_cmd)
        else:
            sign_with_dummy_key(output_apk, dummyks, apksigner_cmd=apksigner_cmd)
    replace_meta(extracted_meta, output_apk, zip_cmd=zip_cmd, date_time=date_time)
    if extracted_v2_sig is not None:
        patch_v2_sig(extracted_v2_sig, output_apk)


def do_extract(signed_apk, output_dir, v1_only=NO):
    """Extract signatures from signed_apk and save in output_dir."""
    v1_only = noautoyes(v1_only)
    extracted_meta = extract_meta(signed_apk)
    for info, data in extracted_meta:
        name = os.path.basename(info.filename)
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(data)
    if v1_only == YES:
        return
    expected = v1_only == NO
    extracted_v2_sig = extract_v2_sig(signed_apk, expected=expected)
    if extracted_v2_sig is None:
        return
    signed_sb_offset, signed_sb = extracted_v2_sig
    with open(os.path.join(output_dir, SIGOFFSET), "w") as fh:
        fh.write(str(signed_sb_offset) + "\n")
    with open(os.path.join(output_dir, SIGBLOCK), "wb") as fh:
        fh.write(signed_sb)


def do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO,
             dummy_keystore=None, config={}):
    """Patch signatures from metadata_dir onto unsigned_apk and save as output_apk."""
    v1_only = noautoyes(v1_only)
    extracted_meta = []
    for what in "SF RSA MF".split():
        filename, = glob.glob(os.path.join(metadata_dir, "*." + what))
        info = zipfile.ZipInfo("META-INF/" + os.path.basename(filename))
        with open(filename, "rb") as fh:
            data = fh.read()
        extracted_meta.append((info, data))
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        sigoffset_file = os.path.join(metadata_dir, SIGOFFSET)
        sigblock_file = os.path.join(metadata_dir, SIGBLOCK)
        if v1_only == AUTO and not os.path.exists(sigblock_file):
            extracted_v2_sig = None
        else:
            with open(sigoffset_file, "r") as fh:
                signed_sb_offset = int(fh.read())
            with open(sigblock_file, "rb") as fh:
                signed_sb = fh.read()
            extracted_v2_sig = signed_sb_offset, signed_sb
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              dummy_keystore, config=config)


def do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO,
            dummy_keystore=None, config={}):
    """Copy signatures from signed_apk onto unsigned_apk and save as output_apk."""
    v1_only = noautoyes(v1_only)
    extracted_meta = extract_meta(signed_apk)
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        expected = v1_only == NO
        extracted_v2_sig = extract_v2_sig(signed_apk, expected=expected)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              dummy_keystore, config=config)


def main():
    import click

    NAY = click.Choice(NOAUTOYES)

    def zip_config(use_zip, config=None):
        if config is None:
            config = {}
        if use_zip != NO:
            config["zip_cmd"] = ZIP_CMD
        if use_zip == YES and not shutil.which(ZIP_CMD):
            raise click.BadOptionUsage("--use-zip", "zip command not found")
        return config

    @click.group(help="""
        apksigcopier - copy/extract/patch apk signatures
    """)
    @click.version_option(__version__)
    def cli():
        pass

    @cli.command(help="""
        Extract APK signatures from signed APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True)
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
    def extract(*args, **kwargs):
        do_extract(*args, **kwargs)

    @cli.command(help="""
        Patch extracted APK signatures onto unsigned APK.
    """)
    @click.option("--dummy-keystore", type=click.Path(exists=True, dir_okay=False))
    @click.option("--use-zip", type=NAY, default=NO, show_default=True)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True)
    @click.argument("metadata_dir", type=click.Path(exists=True, file_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def patch(*args, use_zip=NO, **kwargs):
        do_patch(*args, config=zip_config(use_zip), **kwargs)

    @cli.command(help="""
        Copy (extract & patch) signatures from signed to unsigned APK.
    """)
    @click.option("--dummy-keystore", type=click.Path(exists=True, dir_okay=False))
    @click.option("--use-zip", type=NAY, default=NO, show_default=True)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True)
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def copy(*args, use_zip=NO, **kwargs):
        do_copy(*args, config=zip_config(use_zip), **kwargs)

    @cli.command(help="""
        Generate dummy key(store).
    """)
    @click.option("--keysize", type=int, default=4096, show_default=True)
    @click.argument("dummy_keystore", type=click.Path(dir_okay=False))
    def gen_dummy(dummy_keystore, keysize):
        gen_dummy_key(dummy_keystore, keysize=keysize)

    # FIXME
    if click.__version__.startswith("7."):
        def autocomplete_path(ctx=None, args=(), incomplete=""):  # pylint: disable=W0613
            head, tail = os.path.split(incomplete)
            return sorted(
                (e.path if head else e.path[2:]) + ("/" if e.is_dir() else "")
                for e in os.scandir(head or ".") if e.name.startswith(tail)
            )

        for command in cli.commands.values():
            for param in command.params:
                if isinstance(param.type, click.Path):
                    param.autocompletion = autocomplete_path

    cli(prog_name=name)


if __name__ == "__main__":
    main()

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
