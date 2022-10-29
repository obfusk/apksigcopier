#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2022 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# --                                                            ; {{{1
#
# File        : apksigcopier
# Maintainer  : FC Stegerman <flx@obfusk.net>
# Date        : 2022-10-23
#
# Copyright   : Copyright (C) 2022  FC Stegerman
# Version     : v1.0.2
# License     : GPLv3+
#
# --                                                            ; }}}1

"""
copy/extract/patch android apk signatures & compare apks

apksigcopier is a tool for copying android APK signatures from a signed APK to
an unsigned one (in order to verify reproducible builds).

It can also be used to compare two APKs with different signatures; this requires
apksigner.


CLI
===

$ apksigcopier extract [OPTIONS] SIGNED_APK OUTPUT_DIR
$ apksigcopier patch [OPTIONS] METADATA_DIR UNSIGNED_APK OUTPUT_APK
$ apksigcopier copy [OPTIONS] SIGNED_APK UNSIGNED_APK OUTPUT_APK
$ apksigcopier compare [OPTIONS] FIRST_APK SECOND_APK

The following environment variables can be set to 1, yes, or true to
override the default behaviour:

* set APKSIGCOPIER_EXCLUDE_ALL_META=1 to exclude all metadata files
* set APKSIGCOPIER_COPY_EXTRA_BYTES=1 to copy extra bytes after data (e.g. a v2 sig)


API
===

>> from apksigcopier import do_extract, do_patch, do_copy, do_compare
>> do_extract(signed_apk, output_dir, v1_only=NO)
>> do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO)
>> do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO)
>> do_compare(first_apk, second_apk, unsigned=False)

You can use False, None, and True instead of NO, AUTO, and YES respectively.

The following global variables (which default to False), can be set to
override the default behaviour:

* set exclude_all_meta=True to exclude all metadata files
* set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
"""

import glob
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

from collections import namedtuple
from typing import Any, BinaryIO, Dict, Iterable, Iterator, Optional, Tuple, Union

__version__ = "1.0.2"
NAME = "apksigcopier"

if sys.version_info >= (3, 8):
    from typing import Literal
    NoAutoYes = Literal["no", "auto", "yes"]
else:
    NoAutoYes = str

DateTime = Tuple[int, int, int, int, int, int]
NoAutoYesBoolNone = Union[NoAutoYes, bool, None]
ZipInfoDataPairs = Iterable[Tuple[zipfile.ZipInfo, bytes]]

SIGBLOCK, SIGOFFSET = "APKSigningBlock", "APKSigningBlockOffset"
NOAUTOYES: Tuple[NoAutoYes, NoAutoYes, NoAutoYes] = ("no", "auto", "yes")
NO, AUTO, YES = NOAUTOYES
APK_META = re.compile(r"^META-INF/([0-9A-Za-z_-]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$")
META_EXT: Tuple[str, ...] = ("SF", "RSA|DSA|EC", "MF")
COPY_EXCLUDE: Tuple[str, ...] = ("META-INF/MANIFEST.MF",)
DATETIMEZERO: DateTime = (1980, 0, 0, 0, 0, 0)
VERIFY_CMD: Tuple[str, ...] = ("apksigner", "verify")

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))

exclude_all_meta = False    # exclude all metadata files in copy_apk()
copy_extra_bytes = False    # copy extra bytes after data in copy_apk()


class APKSigCopierError(Exception):
    """Base class for errors."""


class APKSigningBlockError(APKSigCopierError):
    """Something wrong with the APK Signing Block."""


class NoAPKSigningBlock(APKSigningBlockError):
    """APK Signing Block Missing."""


class ZipError(APKSigCopierError):
    """Something wrong with ZIP file."""


# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _override: Dict[str, Any] = {}

    def __init__(self, zinfo, **override):  # pylint: disable=W0231
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

    COMPRESSLEVEL = 9

    _override = dict(
        compress_type=8,
        create_system=0,
        create_version=20,
        date_time=DATETIMEZERO,
        external_attr=0,
        extract_version=20,
        flag_bits=0x800,
    )


def noautoyes(value: NoAutoYesBoolNone) -> NoAutoYes:
    """
    Turns False into NO, None into AUTO, and True into YES.

    >>> from apksigcopier import noautoyes, NO, AUTO, YES
    >>> noautoyes(False) == NO == noautoyes(NO)
    True
    >>> noautoyes(None) == AUTO == noautoyes(AUTO)
    True
    >>> noautoyes(True) == YES == noautoyes(YES)
    True

    """
    if isinstance(value, str):
        if value not in NOAUTOYES:
            raise ValueError("expected NO, AUTO, or YES")
        return value
    try:
        return {False: NO, None: AUTO, True: YES}[value]
    except KeyError:
        raise ValueError("expected False, None, or True")   # pylint: disable=W0707


def is_meta(filename: str) -> bool:
    """
    Returns whether filename is a v1 (JAR) signature file (.SF), signature block
    file (.RSA, .DSA, or .EC), or manifest (MANIFEST.MF).

    See https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    """
    return APK_META.fullmatch(filename) is not None


def exclude_from_copying(filename: str) -> bool:
    """
    Returns whether to exclude a file during copy_apk().

    Excludes filenames in COPY_EXCLUDE (i.e. MANIFEST.MF) by default; when
    exclude_all_meta is set to True instead, excludes all metadata files as
    matched by is_meta().
    """
    return is_meta(filename) if exclude_all_meta else filename in COPY_EXCLUDE


################################################################################
#
# https://en.wikipedia.org/wiki/ZIP_(file_format)
# https://source.android.com/security/apksigning/v2#apk-signing-block-format
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
#
################################################################################


# FIXME: makes certain assumptions and doesn't handle all valid ZIP files!
def copy_apk(unsigned_apk: str, output_apk: str) -> DateTime:
    """
    Copy APK like apksigner would, excluding files matched by
    exclude_from_copying().

    Returns max date_time.

    The following global variables (which default to False), can be set to
    override the default behaviour:

    * set exclude_all_meta=True to exclude all metadata files
    * set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
    """
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
    zdata = zip_data(unsigned_apk)
    offsets = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        for info in sorted(infos, key=lambda info: info.header_offset):
            off_i = fhi.tell()
            if info.header_offset > off_i:
                # copy extra bytes
                fho.write(fhi.read(info.header_offset - off_i))
            hdr = fhi.read(30)
            if hdr[:4] != b"\x50\x4b\x03\x04":
                raise ZipError("Expected local file header signature")
            n, m = struct.unpack("<HH", hdr[26:30])
            hdr += fhi.read(n + m)
            skip = exclude_from_copying(info.filename)
            if skip:
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                if info.filename in offsets:
                    raise ZipError("Duplicate ZIP entry: " + info.filename)
                offsets[info.filename] = off_o = fho.tell()
                if info.compress_type == 0 and off_o != info.header_offset:
                    hdr = _realign_zip_entry(info, hdr, n, m, off_o)
                fho.write(hdr)
                _copy_bytes(fhi, fho, info.compress_size)
            if info.flag_bits & 0x08:
                data_descriptor = fhi.read(12)
                if data_descriptor[:4] == b"\x50\x4b\x07\x08":
                    data_descriptor += fhi.read(4)
                if not skip:
                    fho.write(data_descriptor)
        extra_bytes = zdata.cd_offset - fhi.tell()
        if copy_extra_bytes:
            _copy_bytes(fhi, fho, extra_bytes)
        else:
            fhi.seek(extra_bytes, os.SEEK_CUR)
        cd_offset = fho.tell()
        for info in infos:
            hdr = fhi.read(46)
            if hdr[:4] != b"\x50\x4b\x01\x02":
                raise ZipError("Expected central directory file header signature")
            n, m, k = struct.unpack("<HHH", hdr[28:34])
            hdr += fhi.read(n + m + k)
            if not exclude_from_copying(info.filename):
                off = int.to_bytes(offsets[info.filename], 4, "little")
                hdr = hdr[:42] + off + hdr[46:]
                fho.write(hdr)
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return max(info.date_time for info in infos)


# NB: doesn't sync local & CD headers!
def _realign_zip_entry(info: zipfile.ZipInfo, hdr: bytes, n: int, m: int, off_o: int) -> bytes:
    align = 4096 if info.filename.endswith(".so") else 4
    old_off = 30 + n + m + info.header_offset
    new_off = 30 + n + m + off_o
    old_xtr = info.extra
    new_xtr = b""
    while len(old_xtr) >= 4:
        hdr_id, size = struct.unpack("<HH", old_xtr[:4])
        if size > len(old_xtr) - 4:
            break
        if not (hdr_id == 0 and size == 0):
            if hdr_id == 0xd935:
                if size >= 2:
                    align = int.from_bytes(old_xtr[4:6], "little")
            else:
                new_xtr += old_xtr[:size + 4]
        old_xtr = old_xtr[size + 4:]
    if old_off % align == 0 and new_off % align != 0:
        pad = (align - (new_off - m + len(new_xtr) + 6) % align) % align
        xtr = new_xtr + struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
        m_b = int.to_bytes(len(xtr), 2, "little")
        hdr = hdr[:28] + m_b + hdr[30:30 + n] + xtr
    return hdr


def _copy_bytes(fhi: BinaryIO, fho: BinaryIO, size: int, blocksize: int = 4096) -> None:
    while size > 0:
        data = fhi.read(min(size, blocksize))
        if not data:
            break
        size -= len(data)
        fho.write(data)
    if size != 0:
        raise ZipError("Unexpected EOF")


def extract_meta(signed_apk: str) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    """
    Extract v1 signature metadata files from signed APK.

    Yields (ZipInfo, data) pairs.
    """
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def patch_meta(extracted_meta: ZipInfoDataPairs, output_apk: str,
               date_time: DateTime = DATETIMEZERO) -> None:
    """Add v1 signature metadata to APK (removes v2 sig block, if any)."""
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        for info in zf_out.infolist():
            if is_meta(info.filename):
                raise ZipError("Unexpected metadata")
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        info_data = [(APKZipInfo(info, date_time=date_time), data)
                     for info, data in extracted_meta]
        _write_to_zip(info_data, zf_out)


if sys.version_info >= (3, 7):
    def _write_to_zip(info_data: ZipInfoDataPairs, zf_out: zipfile.ZipFile) -> None:
        for info, data in info_data:
            zf_out.writestr(info, data, compresslevel=APKZipInfo.COMPRESSLEVEL)
else:
    def _write_to_zip(info_data: ZipInfoDataPairs, zf_out: zipfile.ZipFile) -> None:
        old = zipfile._get_compressor
        zipfile._get_compressor = lambda _: zlib.compressobj(APKZipInfo.COMPRESSLEVEL, 8, -15)
        try:
            for info, data in info_data:
                zf_out.writestr(info, data)
        finally:
            zipfile._get_compressor = old


def extract_v2_sig(apkfile: str, expected: bool = True) -> Optional[Tuple[int, bytes]]:
    """
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    NoAPKSigningBlock when expected is True, else returns None.
    """
    cd_offset = zip_data(apkfile).cd_offset
    with open(apkfile, "rb") as fh:
        fh.seek(cd_offset - 16)
        if fh.read(16) != b"APK Sig Block 42":
            if expected:
                raise NoAPKSigningBlock("No APK Signing Block")
            return None
        fh.seek(-24, os.SEEK_CUR)
        sb_size2 = int.from_bytes(fh.read(8), "little")
        fh.seek(-sb_size2 + 8, os.SEEK_CUR)
        sb_size1 = int.from_bytes(fh.read(8), "little")
        if sb_size1 != sb_size2:
            raise APKSigningBlockError("APK Signing Block sizes not equal")
        fh.seek(-8, os.SEEK_CUR)
        sb_offset = fh.tell()
        sig_block = fh.read(sb_size2 + 8)
    return sb_offset, sig_block


def zip_data(apkfile: str, count: int = 1024) -> ZipData:
    """
    Extract central directory, EOCD, and offsets from ZIP.

    Returns ZipData.
    """
    with open(apkfile, "rb") as fh:
        fh.seek(-count, os.SEEK_END)
        data = fh.read()
        pos = data.rfind(b"\x50\x4b\x05\x06")
        if pos == -1:
            raise ZipError("Expected end of central directory record (EOCD)")
        fh.seek(pos - len(data), os.SEEK_CUR)
        eocd_offset = fh.tell()
        fh.seek(16, os.SEEK_CUR)
        cd_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(cd_offset)
        cd_and_eocd = fh.read()
    return ZipData(cd_offset, eocd_offset, cd_and_eocd)


# FIXME: can we determine signed_sb_offset?
def patch_v2_sig(extracted_v2_sig: Tuple[int, bytes], output_apk: str) -> None:
    """Implant extracted v2/v3 signature into APK."""
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(output_apk)
    if signed_sb_offset < data_out.cd_offset:
        raise APKSigningBlockError("APK Signing Block offset < central directory offset")
    padding = b"\x00" * (signed_sb_offset - data_out.cd_offset)
    offset = len(signed_sb) + len(padding)
    with open(output_apk, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


def patch_apk(extracted_meta: ZipInfoDataPairs, extracted_v2_sig: Optional[Tuple[int, bytes]],
              unsigned_apk: str, output_apk: str) -> None:
    """
    Patch extracted_meta + extracted_v2_sig (if not None) onto unsigned_apk and
    save as output_apk.
    """
    date_time = copy_apk(unsigned_apk, output_apk)
    patch_meta(extracted_meta, output_apk, date_time=date_time)
    if extracted_v2_sig is not None:
        patch_v2_sig(extracted_v2_sig, output_apk)


def verify_apk(apk: str, min_sdk_version: Optional[int] = None) -> None:
    """Verifies APK using apksigner."""
    args = VERIFY_CMD
    if min_sdk_version is not None:
        args += ("--min-sdk-version={}".format(min_sdk_version),)
    args += ("--", apk)
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise APKSigCopierError("failed to verify " + apk)  # pylint: disable=W0707
    except FileNotFoundError:
        raise APKSigCopierError("{} command not found".format(VERIFY_CMD[0]))   # pylint: disable=W0707


def do_extract(signed_apk: str, output_dir: str, v1_only: NoAutoYesBoolNone = NO) -> None:
    """
    Extract signatures from signed_apk and save in output_dir.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = tuple(extract_meta(signed_apk))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing metadata files in signed_apk")
    for info, data in extracted_meta:
        name = os.path.basename(info.filename)
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(data)
    if v1_only == YES:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 signature")
        return
    expected = v1_only == NO
    extracted_v2_sig = extract_v2_sig(signed_apk, expected=expected)
    if extracted_v2_sig is None:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
        return
    signed_sb_offset, signed_sb = extracted_v2_sig
    with open(os.path.join(output_dir, SIGOFFSET), "w") as fh:
        fh.write(str(signed_sb_offset) + "\n")
    with open(os.path.join(output_dir, SIGBLOCK), "wb") as fh:
        fh.write(signed_sb)


def do_patch(metadata_dir: str, unsigned_apk: str, output_apk: str,
             v1_only: NoAutoYesBoolNone = NO) -> None:
    """
    Patch signatures from metadata_dir onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = []
    for pat in META_EXT:
        files = [fn for ext in pat.split("|") for fn in
                 glob.glob(os.path.join(metadata_dir, "*." + ext))]
        if len(files) != 1:
            continue
        info = zipfile.ZipInfo("META-INF/" + os.path.basename(files[0]))
        with open(files[0], "rb") as fh:
            extracted_meta.append((info, fh.read()))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing files in metadata_dir")
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
    if not extracted_meta and extracted_v2_sig is None:
        raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk)


def do_copy(signed_apk: str, unsigned_apk: str, output_apk: str,
            v1_only: NoAutoYesBoolNone = NO) -> None:
    """
    Copy signatures from signed_apk onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = extract_meta(signed_apk)
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        extracted_v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk)


def do_compare(first_apk: str, second_apk: str, unsigned: bool = False,
               min_sdk_version: Optional[int] = None) -> None:
    """
    Compare first_apk to second_apk by:
    * using apksigner to check if the first APK verifies
    * checking if the second APK also verifies (unless unsigned is True)
    * copying the signature from first_apk to a copy of second_apk
    * checking if the resulting APK verifies
    """
    global exclude_all_meta
    verify_apk(first_apk, min_sdk_version=min_sdk_version)
    if not unsigned:
        verify_apk(second_apk, min_sdk_version=min_sdk_version)
    with tempfile.TemporaryDirectory() as tmpdir:
        output_apk = os.path.join(tmpdir, "output.apk")        # FIXME
        old_exclude_all_meta = exclude_all_meta                # FIXME
        exclude_all_meta = not unsigned
        try:
            do_copy(first_apk, second_apk, output_apk, AUTO)
        finally:
            exclude_all_meta = old_exclude_all_meta
        verify_apk(output_apk, min_sdk_version=min_sdk_version)


def main():
    """CLI; requires click."""

    global exclude_all_meta, copy_extra_bytes
    exclude_all_meta = os.environ.get("APKSIGCOPIER_EXCLUDE_ALL_META") in ("1", "yes", "true")
    copy_extra_bytes = os.environ.get("APKSIGCOPIER_COPY_EXTRA_BYTES") in ("1", "yes", "true")

    import click

    NAY = click.Choice(NOAUTOYES)

    @click.group(help="""
        apksigcopier - copy/extract/patch android apk signatures & compare apks
    """)
    @click.version_option(__version__)
    def cli():
        pass

    @cli.command(help="""
        Extract APK signatures from signed APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
    def extract(*args, **kwargs):
        do_extract(*args, **kwargs)

    @cli.command(help="""
        Patch extracted APK signatures onto unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.argument("metadata_dir", type=click.Path(exists=True, file_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def patch(*args, **kwargs):
        do_patch(*args, **kwargs)

    @cli.command(help="""
        Copy (extract & patch) signatures from signed to unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def copy(*args, **kwargs):
        do_copy(*args, **kwargs)

    @cli.command(help="""
        Compare two APKs by copying the signature from the first to a copy of
        the second and checking if the resulting APK verifies.

        This command requires apksigner.
    """)
    @click.option("--unsigned", is_flag=True, help="Accept unsigned SECOND_APK.")
    @click.option("--min-sdk-version", type=click.INT, help="Passed to apksigner.")
    @click.argument("first_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("second_apk", type=click.Path(exists=True, dir_okay=False))
    def compare(*args, **kwargs):
        do_compare(*args, **kwargs)

    # FIXME: click autocompletion is broken and this workaround fails w/ >= 8.0
    if click.__version__.startswith("7."):
        def autocomplete_path(ctx=None, args=(), incomplete=""):    # pylint: disable=W0613
            head, tail = os.path.split(os.path.expanduser(incomplete))
            return sorted(
                (e.path if head else e.path[2:]) + ("/" if e.is_dir() else "")
                for e in os.scandir(head or ".") if e.name.startswith(tail)
            )

        for command in cli.commands.values():
            for param in command.params:
                if isinstance(param.type, click.Path):
                    param.autocompletion = autocomplete_path

    try:
        cli(prog_name=NAME)
    except APKSigCopierError as e:
        click.echo("Error: {}.".format(e), err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
