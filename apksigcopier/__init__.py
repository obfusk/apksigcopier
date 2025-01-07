#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
copy/extract/patch android apk signatures & compare apks

apksigcopier is a tool that enables using an android APK signature as a build
input (by copying it from a signed APK to an unsigned one), making it possible
to create a (bit-by-bit identical) reproducible build from the source code
without having access to the private key used to create the signature.

It can also be used to verify that two APKs with different signatures are
otherwise identical; this requires apksigner.


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
* set APKSIGCOPIER_SKIP_REALIGNMENT=1 to skip realignment of ZIP entries
* set APKSIGCOPIER_LEGACY_V1SIGFILE=1 to use the legacy v1 signature files format


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
* set skip_realignment=True to skip realignment of ZIP entries
* set legacy_v1sigfile=True to use the legacy v1 signature files format
"""

import glob
import io
import json
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

from collections import namedtuple
from typing import (Any, BinaryIO, Callable, Dict, Iterable, Iterator, List, Optional,
                    Set, Tuple, Union)

__version__ = "1.1.1"
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
V1SIGZIP = "v1signature.zip"
DIFF_JSON = "differences.json"

NOAUTOYES: Tuple[NoAutoYes, NoAutoYes, NoAutoYes] = ("no", "auto", "yes")
NO, AUTO, YES = NOAUTOYES

JAR_MANIFEST = "META-INF/MANIFEST.MF"
JAR_SBF_EXTS = ("RSA", "DSA", "EC")

# NB: subdirectories should be skipped per the spec but android doesn't
APK_META = re.compile(r"\AMETA-INF/((?s:.)*\.(SF|RSA|DSA|EC)|MANIFEST\.MF)\Z")
APK_META_STRICT = re.compile(r"\AMETA-INF/([0-9A-Za-z_-]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)\Z")

META_EXT: Tuple[str, ...] = ("SF", "|".join(JAR_SBF_EXTS), "MF")
COPY_EXCLUDE: Tuple[str, ...] = (JAR_MANIFEST,)

DATETIMEZERO: DateTime = (1980, 0, 0, 0, 0, 0)
MAX_SIGNERS = 10
VERIFY_CMD: Tuple[str, ...] = ("apksigner", "verify")

################################################################################
#
# NB: these values are all from apksigner (the first element of each tuple, same
# as APKZipInfo) or signflinger/zipflinger, except for external_attr w/ 0664
# permissions and flag_bits 0x08, added for completeness.
#
# NB: zipflinger changed from 0666 to 0644 in commit 895ba5fba6ab84617dd67e38f456a8f96aa37ff0
#
# https://android.googlesource.com/platform/tools/apksig
#   src/main/java/com/android/apksig/internal/zip/{CentralDirectoryRecord,LocalFileRecord,ZipUtils}.java
# https://android.googlesource.com/platform/tools/base
#   signflinger/src/com/android/signflinger/SignedApk.java
#   zipflinger/src/com/android/zipflinger/{CentralDirectoryRecord,LocalFileHeader,Source}.java
#
################################################################################

VALID_VERSION_CREATED_SYS = (0, 3)              # fat, unx
VALID_VERSION_CREATED_VSN = (20, 0, 24)         # 2.0, 0.0, 2.4
VALID_VERSION_EXTRACT = (20, 0)                 # 2.0, 0.0
VALID_FLAGS_MASK = 0x808                        # 0x800 = utf8, 0x08 = data_descriptor
VALID_EXTERNAL_ATTRS_MASK = 0o100666 << 16      # regular file + mode bits

# NB: superseded by the new extract_v1_sig() format
VALID_ZIP_META = dict(
    compresslevel=(9, 1),                       # best compression, best speed
    create_system=VALID_VERSION_CREATED_SYS,    # see above
    create_version=VALID_VERSION_CREATED_VSN,   # see above
    external_attr=(0,                           # N/A
                   0o100644 << 16,              # regular file rw-r--r--
                   0o100664 << 16,              # regular file rw-rw-r--
                   0o100666 << 16),             # regular file rw-rw-rw-
    extract_version=VALID_VERSION_EXTRACT,      # see above
    flag_bits=(0x800, 0, 0x08, 0x808),          # see above
)

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))

exclude_all_meta = False    # exclude all metadata files in copy_apk()
copy_extra_bytes = False    # copy extra bytes after data in copy_apk()
skip_realignment = False    # skip realignment of ZIP entries in copy_apk()
legacy_v1sigfile = False    # use the legacy v1 signature files format


class APKSigCopierError(Exception):
    """Base class for errors."""


class APKSigningBlockError(APKSigCopierError):
    """Something wrong with the APK Signing Block."""


class NoAPKSigningBlock(APKSigningBlockError):
    """APK Signing Block Missing."""


class ZipError(APKSigCopierError):
    """Something wrong with ZIP file."""


# NB: superseded by the new extract_v1_sig() format
# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack (legacy)."""

    _override: Dict[str, Any] = {}

    def __init__(self, zinfo: zipfile.ZipInfo, **override: Any) -> None:
        # pylint: disable=W0231
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name: str) -> Any:
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


# See VALID_ZIP_META
class APKZipInfo(ReproducibleZipInfo):
    """Reproducible ZipInfo for APK files (legacy)."""

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
    r"""
    Turns False into NO, None into AUTO, and True into YES.

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


def is_meta(filename: str, strict: bool = False) -> bool:
    r"""
    Returns whether filename is a v1 (JAR) signature file (.SF), signature block
    file (.RSA, .DSA, or .EC), or manifest (MANIFEST.MF).

    See https://docs.oracle.com/en/java/javase/21/docs/specs/jar/jar.html

    NB: if strict=True doesn't match signature (block) files in subdirectories
    like android does and only considers file names valid if they are
    alphanumeric ASCII.

    >>> is_meta("classes.dex")
    False
    >>> is_meta("META-INF/CERT.SF")
    True
    >>> is_meta("META-INF/CERT.RSA")
    True
    >>> is_meta("META-INF/MANIFEST.MF")
    True
    >>> is_meta("META-INF/OOPS")
    False
    >>> is_meta("META-INF/oops/CERT.RSA")
    True
    >>> is_meta("META-INF/oops/CERT.RSA", strict=True)
    False
    >>> is_meta("META-INF/猫\n.RSA")
    True
    >>> is_meta("META-INF/猫\n.RSA", strict=True)
    False

    """
    return bool((APK_META_STRICT if strict else APK_META).fullmatch(filename))


def exclude_from_copying(filename: str) -> bool:
    r"""
    Returns whether to exclude a file during copy_apk().

    Excludes filenames in COPY_EXCLUDE (i.e. MANIFEST.MF) by default; when
    exclude_all_meta is set to True instead, excludes all metadata files as
    matched by is_meta().

    Directories are always excluded.

    >>> exclude_from_copying("classes.dex")
    False
    >>> exclude_from_copying("foo/")
    True
    >>> exclude_from_copying("META-INF/")
    True
    >>> exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> exclude_from_copying("META-INF/CERT.SF")
    False
    >>> exclude_from_copying("META-INF/OOPS")
    False

    >>> import apksigcopier as asc
    >>> asc.exclude_all_meta = True
    >>> asc.exclude_from_copying("classes.dex")
    False
    >>> asc.exclude_from_copying("META-INF/")
    True
    >>> asc.exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> asc.exclude_from_copying("META-INF/CERT.SF")
    True
    >>> asc.exclude_from_copying("META-INF/OOPS")
    False

    """
    return exclude_meta(filename) if exclude_all_meta else exclude_default(filename)


def exclude_default(filename: str) -> bool:
    """
    Like exclude_from_copying(); excludes directories and filenames in
    COPY_EXCLUDE (i.e. MANIFEST.MF).
    """
    return is_directory(filename) or filename in COPY_EXCLUDE


def exclude_meta(filename: str) -> bool:
    """Like exclude_from_copying(); excludes directories and all metadata files."""
    return is_directory(filename) or is_meta(filename)


def is_directory(filename: str) -> bool:
    """ZIP entries with filenames that end with a '/' are directories."""
    return filename.endswith("/")


################################################################################
#
# There is usually a 132-byte virtual entry at the start of an APK signed with a
# v1 signature by signflinger/zipflinger; almost certainly this is a default
# manifest ZIP entry created at initialisation, deleted (from the CD but not
# from the file) during v1 signing, and eventually replaced by a virtual entry.
#
#   >>> (30 + len("META-INF/MANIFEST.MF") +
#   ...       len("Manifest-Version: 1.0\r\n"
#   ...           "Created-By: Android Gradle 7.1.3\r\n"
#   ...           "Built-By: Signflinger\r\n\r\n"))
#   132
#
# NB: they could be a different size, depending on Created-By and Built-By.
#
# FIXME: could virtual entries occur elsewhere as well?
#
# https://android.googlesource.com/platform/tools/base
#   signflinger/src/com/android/signflinger/SignedApk.java
#   zipflinger/src/com/android/zipflinger/{LocalFileHeader,ZipArchive}.java
#
################################################################################

def zipflinger_virtual_entry(size: int) -> bytes:
    """Create zipflinger virtual entry."""
    if size < 30:
        raise ValueError("Minimum size for virtual entries is 30 bytes")
    return (
        # header            extract_version     flag_bits
        b"\x50\x4b\x03\x04" b"\x00\x00"         b"\x00\x00"
        # compress_type     (1981,1,1,1,1,2)    crc32
        b"\x00\x00"         b"\x21\x08\x21\x02" b"\x00\x00\x00\x00"
        # compress_size     file_size           filename length
        b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00"
    ) + int.to_bytes(size - 30, 2, "little") + b"\x00" * (size - 30)


def detect_zfe(apkfile: str) -> Optional[int]:
    """
    Detect zipflinger virtual entry.

    Returns the size of the virtual entry if found, None otherwise.

    Raises ZipError if the size is less than 30 or greater than 4096, or the
    data isn't all zeroes.
    """
    with open(apkfile, "rb") as fh:
        zfe_start = zipflinger_virtual_entry(30)[:28]   # w/o len(extra)
        if fh.read(28) == zfe_start:
            zfe_size = 30 + int.from_bytes(fh.read(2), "little")
            if not (30 <= zfe_size <= 4096):
                raise ZipError("Unsupported virtual entry size")
            if not fh.read(zfe_size - 30) == b"\x00" * (zfe_size - 30):
                raise ZipError("Unsupported virtual entry data")
            return zfe_size
    return None


################################################################################
#
# https://en.wikipedia.org/wiki/ZIP_(file_format)
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
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
# FIXME: support zip64?
# FIXME: handle utf8 filenames w/o utf8 flag (as produced by zipflinger)?
# https://android.googlesource.com/platform/tools/apksig
#   src/main/java/com/android/apksig/ApkSigner.java
def copy_apk(unsigned_apk: str, output_apk: str, *,
             copy_extra: Optional[bool] = None,
             exclude: Optional[Callable[[str], bool]] = None,
             realign: Optional[bool] = None, zfe_size: Optional[int] = None,
             v1_sig: Optional[bytes] = None) -> DateTime:
    r"""
    Copy APK like apksigner would, excluding files matched by exclude_from_copying().

    Copies a v1 signature if v1_sig is provided; adds a zipflinger virtual entry
    of zfe_size bytes if one is not already present and zfe_size is not None;
    returns max date_time.

    The following global variables (which default to False), can be set to
    override the default behaviour:

    * set exclude_all_meta=True to exclude all metadata files
    * set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
    * set skip_realignment=True to skip realignment of ZIP entries

    The default behaviour can also be changed using the keyword-only arguments
    exclude, copy_extra, and realign; these take precedence over the global
    variables when not None.  NB: exclude is a callable, not a bool; realign is
    the inverse of skip_realignment.

    >>> apk = "test/apks/apks/golden-aligned-in.apk"
    >>> with zipfile.ZipFile(apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     copy_apk(apk, out)
    ...     with zipfile.ZipFile(out, "r") as zf:
    ...         infos_out = zf.infolist()
    (2017, 5, 15, 11, 28, 40)
    >>> for i in infos_in:
    ...     print(i.orig_filename)
    META-INF/
    META-INF/MANIFEST.MF
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> for i in infos_out:
    ...     print(i.orig_filename)
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> infos_in[2]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> infos_out[0]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> repr(infos_in[2:]) == repr(infos_out)
    True

    """
    if copy_extra is None:
        copy_extra = copy_extra_bytes
    if exclude is None:
        exclude = exclude_from_copying
    if realign is None:
        realign = not skip_realignment
    if v1_sig:
        v1_sig_fhi = io.BytesIO(v1_sig)
        v1_infos, v1_datas, v1_comment_data, v1_indices, v1_offsets = extract_v1_sig_data(v1_sig_fhi)
        if "zfe_size" in v1_comment_data and not zfe_size:
            zfe_size = int(v1_comment_data["zfe_size"])
        v1_cd_offset = _zip_data(v1_sig_fhi, count=min(65536, len(v1_sig))).cd_offset
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
        if v1_sig and (error := validate_v1_sig(v1_infos, v1_datas, zf)):
            raise APKSigCopierError(f"Invalid v1_sig: {error}")
    if v1_sig and any((is_meta(info.orig_filename) or is_meta(info.orig_filename.split("\x00", 1)[0]))
                      and not exclude(info.orig_filename) for info in infos):   # noqa: W503
        raise APKSigCopierError("Unexcluded metadata file(s)")
    zdata = zip_data(unsigned_apk)
    offsets: Dict[str, int] = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        if zfe_size:
            zfe = zipflinger_virtual_entry(zfe_size)
            if fhi.read(zfe_size) != zfe:
                fho.write(zfe)
            fhi.seek(0)
        for info in sorted(infos, key=lambda info: info.header_offset):
            off_i = fhi.tell()
            if info.header_offset > off_i:
                # copy extra bytes
                fho.write(fhi.read(info.header_offset - off_i))
            off_o = fho.tell()
            while v1_sig and off_o in v1_offsets:
                # FIXME: can these be STORED and need alignment?
                # try to match original header offsets (for entries not at the end)
                copy_v1_sig_entries(v1_sig_fhi, fho, [v1_infos[v1_offsets[off_o]]],
                                    v1_datas, offsets)
                del v1_offsets[off_o]
                off_o = fho.tell()
            hdr, n, m = _read_lfh(fhi)
            if skip := exclude(info.orig_filename):
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                if info.orig_filename in offsets:
                    raise ZipError(f"Duplicate ZIP entry: {info.orig_filename!r}")
                offsets[info.orig_filename] = off_o
                if realign and info.compress_type == 0 and off_o != info.header_offset:
                    hdr = _realign_zip_entry(info, hdr, n, m, off_o,
                                             pad_like_apksigner=not zfe_size)
                fho.write(hdr)
                _copy_bytes(fhi, fho, info.compress_size)
            if (data_descriptor := _read_data_descriptor(fhi, info)) and not skip:
                fho.write(data_descriptor)
        if v1_sig and v1_offsets:
            # copy (remaining) entries at the end
            copy_v1_sig_entries(v1_sig_fhi, fho, [v1_infos[i] for i in v1_offsets.values()],
                                v1_datas, offsets)
        extra_bytes = zdata.cd_offset - fhi.tell()
        if copy_extra:
            _copy_bytes(fhi, fho, extra_bytes)
        else:
            fhi.seek(extra_bytes, os.SEEK_CUR)
        cd_offset = fho.tell()
        idx_o = 0
        for info in infos:
            while v1_sig and idx_o in v1_indices:
                # try to match original CD position (for entries not at the end)
                v1_sig_fhi.seek(v1_cd_offset)
                copy_v1_sig_cd_entries(v1_sig_fhi, fho, v1_infos, v1_datas, offsets,
                                       only={v1_indices[idx_o]})
                del v1_indices[idx_o]
                idx_o += 1
            hdr, n, m, k = _read_cdfh(fhi)
            if not exclude(info.orig_filename):
                fho.write(_adjust_offset(hdr, offsets[info.orig_filename]))
                idx_o += 1
        if v1_sig and v1_indices:
            # copy (remaining) entries at the end
            v1_sig_fhi.seek(v1_cd_offset)
            copy_v1_sig_cd_entries(v1_sig_fhi, fho, v1_infos, v1_datas, offsets,
                                   only=set(v1_indices.values()))
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return max(info.date_time for info in infos if not exclude(info.orig_filename))


def _read_lfh(fh: BinaryIO) -> Tuple[bytes, int, int]:
    hdr = fh.read(30)
    if hdr[:4] != b"\x50\x4b\x03\x04":
        raise ZipError("Expected local file header signature")
    n, m = struct.unpack("<HH", hdr[26:30])
    return hdr + fh.read(n + m), n, m


def _read_cdfh(fh: BinaryIO) -> Tuple[bytes, int, int, int]:
    hdr = fh.read(46)
    if hdr[:4] != b"\x50\x4b\x01\x02":
        raise ZipError("Expected central directory file header signature")
    n, m, k = struct.unpack("<HHH", hdr[28:34])
    return hdr + fh.read(n + m + k), n, m, k


def _adjust_offset(hdr: bytes, offset: int) -> bytes:
    return hdr[:42] + int.to_bytes(offset, 4, "little") + hdr[46:]


def _read_data_descriptor(fh: BinaryIO, info: zipfile.ZipInfo) -> Optional[bytes]:
    if info.flag_bits & 0x08:
        data_descriptor = fh.read(12)
        if data_descriptor[:4] == b"\x50\x4b\x07\x08":
            data_descriptor += fh.read(4)
        return data_descriptor
    return None


# NB: doesn't sync local & CD headers!
def _realign_zip_entry(info: zipfile.ZipInfo, hdr: bytes, n: int, m: int,
                       off_o: int, pad_like_apksigner: bool = True) -> bytes:
    align = 4096 if info.orig_filename.endswith(".so") else 4
    old_off = 30 + n + m + info.header_offset
    new_off = 30 + n + m + off_o
    old_xtr = hdr[30 + n:30 + n + m]
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
        if pad_like_apksigner:
            pad = (align - (new_off - m + len(new_xtr) + 6) % align) % align
            xtr = new_xtr + struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
        else:
            pad = (align - (new_off - m + len(new_xtr)) % align) % align
            xtr = new_xtr + pad * b"\x00"
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


def extract_v1_sig(apkfile: str) -> Optional[bytes]:
    r"""
    Extract v1 signature data as ZIP file data.

    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> v1_sig = extract_v1_sig(apk)
    >>> fh = io.BytesIO(v1_sig)
    >>> zf = zipfile.ZipFile(fh, "r")
    >>> [x.orig_filename for x in zf.infolist()]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> for line in zf.read("META-INF/RSA-2048.SF").splitlines()[:4]:
    ...     print(line.decode())
    Signature-Version: 1.0
    Created-By: 1.0 (Android)
    SHA-256-Digest-Manifest: hz7AxDJU9Namxoou/kc4Z2GVRS9anCGI+M52tbCsXT0=
    X-Android-APK-Signed: 2, 3
    >>> for line in zf.read("META-INF/MANIFEST.MF").splitlines()[:2]:
    ...     print(line.decode())
    Manifest-Version: 1.0
    Created-By: 1.8.0_45-internal (Oracle Corporation)
    >>> zf.comment
    b'{"offsets":[[6,5109],[7,5595],[8,6706]]}'
    >>> infos, datas, comment_data, indices, offsets = extract_v1_sig_data(fh)
    >>> [x.orig_filename for x in infos]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> [(k, len(v)) for k, v in datas.items()]
    [('META-INF/RSA-2048.SF', 664), ('META-INF/RSA-2048.RSA', 1160), ('META-INF/MANIFEST.MF', 589)]
    >>> comment_data
    {'offsets': [[6, 5109], [7, 5595], [8, 6706]]}
    >>> indices
    {6: 0, 7: 1, 8: 2}
    >>> offsets
    {5109: 0, 5595: 1, 6706: 2}

    """
    with zipfile.ZipFile(apkfile, "r") as zf:
        infos = zf.infolist()
        metas = [info for info in infos if is_meta(info.orig_filename)]
        datas = {info.orig_filename: zf.read(info) for info in metas}
        coffs = [[i, info.header_offset] for i, info in enumerate(infos) if is_meta(info.orig_filename)]
    comment_data: Dict[str, Any] = dict(offsets=coffs)
    if zfe_size := detect_zfe(apkfile):
        comment_data["zfe_size"] = zfe_size
    comment = json.dumps(comment_data, separators=(",", ":"), sort_keys=True).encode()
    offsets: Dict[str, int] = {}
    fho = io.BytesIO()
    cd_offset_in = zip_data(apkfile).cd_offset
    with open(apkfile, "rb") as fhi:
        copy_v1_sig_entries(fhi, fho, infos, datas, offsets)
        cd_offset = fho.tell()
        fhi.seek(cd_offset_in)
        copy_v1_sig_cd_entries(fhi, fho, infos, datas, offsets)
        eocd_offset = fho.tell()
        fho.write(_eocd(len(offsets), eocd_offset, cd_offset, comment))
    if offsets and (error := validate_v1_sig(metas, datas)):
        raise APKSigCopierError(f"Invalid v1_sig: {error}")
    return fho.getvalue() if offsets else None


def _eocd(entries: int, eocd_offset: int, cd_offset: int, comment: bytes = b"") -> bytes:
    data = struct.pack("<HHHHLLH", 0, 0, entries, entries, eocd_offset - cd_offset,
                       cd_offset, len(comment))
    return b"\x50\x4b\x05\x06" + data + comment


def copy_v1_sig_entries(fhi: BinaryIO, fho: BinaryIO, infos: List[zipfile.ZipInfo],
                        datas: Dict[str, bytes], offsets: Dict[str, int]) -> None:
    """Copy v1 signature entries."""
    for info in sorted(infos, key=lambda info: info.header_offset):
        if not is_meta(info.orig_filename):
            continue
        if info.orig_filename in offsets:
            raise ZipError(f"Duplicate ZIP entry: {info.orig_filename!r}")
        fhi.seek(info.header_offset)
        hdr, n, m = _read_lfh(fhi)
        offsets[info.orig_filename] = fho.tell()
        fho.write(hdr)
        _copy_bytes(fhi, fho, info.compress_size)
        if data_descriptor := _read_data_descriptor(fhi, info):
            fho.write(data_descriptor)
        if error := validate_zip_header(hdr, info, datas, data_descriptor):
            raise ZipError(f"Unsupported LFH for {info.orig_filename!r}: {error}")


def copy_v1_sig_cd_entries(fhi: BinaryIO, fho: BinaryIO, infos: List[zipfile.ZipInfo],
                           datas: Dict[str, bytes], offsets: Dict[str, int],
                           *, only: Optional[Set[int]] = None) -> None:
    """Copy v1 signature CD entries."""
    for i, info in enumerate(infos):
        hdr, n, m, k = _read_cdfh(fhi)
        if not is_meta(info.orig_filename) or (only is not None and i not in only):
            continue
        if error := validate_zip_header(hdr, info, datas):
            raise ZipError(f"Unsupported CDFH for {info.orig_filename!r}: {error}")
        fho.write(_adjust_offset(hdr, offsets[info.orig_filename]))


def validate_zip_header(hdr: bytes, info: zipfile.ZipInfo, datas: Dict[str, bytes],
                        data_descriptor: Optional[bytes] = None) -> Optional[str]:
    """
    Validate ZIP LHF or CDFH.

    Returns None if valid, error otherwise.
    """
    if hdr[:4] == b"\x50\x4b\x03\x04":  # LFH
        (version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
            uncompressed_size, n, m) = struct.unpack("<HHHHHIIIHH", hdr[4:30])
        filename = hdr[30:30 + n]
        extra = hdr[30 + n:30 + n + m]
        if data_descriptor:
            old = crc32, compressed_size, uncompressed_size
            new = struct.unpack("<III", data_descriptor[-12:])
            crc32, compressed_size, uncompressed_size = new
            for a, b in zip(old, new):
                if a not in (0, b):
                    return "data descriptor mismatch"
        version_created = start_disk = internal_attrs = external_attrs = 0
        comment = b""
    else:                               # CDFH
        (version_created, version_extract, flags, compression_method, mtime, mdate, crc32,
            compressed_size, uncompressed_size, n, m, k, start_disk, internal_attrs,
            external_attrs, header_offset) = struct.unpack("<HHHHHHIIIHHHHHII", hdr[4:46])
        filename = hdr[46:46 + n]
        extra = hdr[46 + n:46 + n + m]
        comment = hdr[46 + n + m:46 + n + m + k]
    version_created_sys, version_created_vsn = version_created >> 8, version_created & 0xFF
    if version_created_sys not in VALID_VERSION_CREATED_SYS:
        return f"unsupported created system: {version_created_sys}"
    if version_created_vsn not in VALID_VERSION_CREATED_VSN:
        return f"unsupported created version: {version_created_vsn}"
    if version_extract not in VALID_VERSION_EXTRACT:
        return f"unsupported extract version: {version_extract}"
    if flags | VALID_FLAGS_MASK != VALID_FLAGS_MASK:
        return f"unsupported flags: {hex(flags)}"
    if flags != info.flag_bits:
        return "flags mismatch"
    if compression_method not in (0, 8):
        return f"unsupported compression method: {compression_method}"
    if compression_method != info.compress_type:
        return "compression method mismatch"
    if crc32 != zlib.crc32(datas[info.orig_filename]):
        return "crc32 mismatch"
    if compressed_size != info.compress_size:
        return "compressed size mismatch"
    if uncompressed_size != len(datas[info.orig_filename]):
        return "uncompressed size mismatch"
    if start_disk:
        return "non-zero start disk"
    if internal_attrs:
        return "non-zero internal attrs"
    if external_attrs | VALID_EXTERNAL_ATTRS_MASK != VALID_EXTERNAL_ATTRS_MASK:
        return f"unsupported external attrs: {hex(external_attrs)}"
    if any(c in filename for c in b"\x00\n\r"):
        return "NUL, LF, or CR in filename"
    if filename.decode() != info.orig_filename:
        return "decoded filename mismatch"
    if extra:
        return "non-empty extra field"
    if comment:
        return "non-empty file comment"
    return None


def extract_v1_sig_data(fhi: BinaryIO) -> Tuple[
        List[zipfile.ZipInfo], Dict[str, bytes], Dict[str, Any],
        Dict[int, int], Dict[int, int]]:
    """
    Extract validated data from v1_sig comment.

    Returns (infos, datas, comment_data, indices, offsets).
    """
    with zipfile.ZipFile(fhi, "r") as zf:
        infos = zf.infolist()
        datas = {info.orig_filename: zf.read(info) for info in infos}
        try:
            comment_data = json.loads(zf.comment.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise APKSigCopierError(f"Invalid {V1SIGZIP} comment: {e}")     # pylint: disable=W0707
        if error := validate_v1_sig_data(comment_data, len(infos)):
            raise APKSigCopierError(f"Invalid {V1SIGZIP} comment: {error}")
    indices = {idx: i for i, (idx, _) in enumerate(comment_data["offsets"])}
    offsets = {off: i for i, (_, off) in enumerate(comment_data["offsets"])}
    return infos, datas, comment_data, indices, offsets


def validate_v1_sig_data(data: Dict[str, Any], n_infos: int) -> Optional[str]:
    r"""
    Validate data from v1_sig comment.

    Returns None if valid, error otherwise.

    >>> validate_v1_sig_data(dict(offsets=[[0, 128], [1, 256]], zfe_size=132), 2) is None
    True
    >>> validate_v1_sig_data(dict(offsets=[[1, 2], [3]]), 2)
    '.offsets[1] is not a list of 2 ints'
    >>> validate_v1_sig_data(dict(offsets=[[0, 42], [1, 42]]), 2)
    '.offsets contains duplicates'
    >>> validate_v1_sig_data(dict(offsets=[[0, 37], [0, 42]]), 2)
    '.offsets contains duplicates'

    """
    if set(data) - {"offsets", "zfe_size"}:
        return "contains unknown key(s)"
    if "offsets" not in data:
        return "missing .offsets"
    if not isinstance(data["offsets"], list):
        return ".offsets is not a list"
    if len(data["offsets"]) != n_infos:
        return ".offsets length does not match number of entries"
    for i, pair in enumerate(data["offsets"]):
        if not isinstance(pair, list) or len(pair) != 2 or \
                not all(type(x) is int for x in pair):
            return f".offsets[{i}] is not a list of 2 ints"
    indices = set(idx for idx, _ in data["offsets"])
    offsets = set(off for _, off in data["offsets"])
    if len(indices) != n_infos or len(offsets) != n_infos:
        return ".offsets contains duplicates"
    if any(idx < 0 for idx in indices) or any(off < 0 for off in offsets):
        return ".offsets contains negative values"
    if "zfe_size" in data:
        if type(data["zfe_size"]) is not int:
            return ".zfe_size is not an int"
        if not (30 <= data["zfe_size"] <= 4096):
            return ".zfe_size is < 30 or > 4096"
    return None


def validate_v1_sig(infos: List[zipfile.ZipInfo], datas: Dict[str, bytes],
                    output_zf: Optional[zipfile.ZipFile] = None) -> Optional[str]:
    r"""
    Validate data from v1_sig.

    NB: does not validate the signature (files)!

    Returns None if valid, error otherwise.

    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> infos, datas, _, _, _ = extract_v1_sig_data(io.BytesIO(extract_v1_sig(apk)))
    >>> [x.orig_filename for x in infos]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> validate_v1_sig(infos, datas) is None
    True
    >>> validate_v1_sig(infos[1:], {})
    "signature file missing for 'META-INF/RSA-2048.RSA'"
    >>> validate_v1_sig([infos[0], infos[2]], {})
    "signature block file mismatch for 'META-INF/RSA-2048.SF'"
    >>> validate_v1_sig(infos + [zipfile.ZipInfo("META-INF/RSA-2048.EC")], {})
    "signature block file mismatch for 'META-INF/RSA-2048.SF'"

    """
    filenames = set(info.orig_filename for info in infos)
    if len(filenames) != len(infos):
        return "duplicate entries"
    if JAR_MANIFEST not in filenames:
        return "missing manifest"
    for info in infos:
        base = info.orig_filename.rsplit(".", 1)[0]
        if not is_meta(info.orig_filename, strict=True):
            return f"not a (proper) metadata file: {info.orig_filename!r}"
        if info.orig_filename.endswith(".SF"):
            if sum(1 for ext in JAR_SBF_EXTS if f"{base}.{ext}" in filenames) != 1:
                return f"signature block file mismatch for {info.orig_filename!r}"
        elif any(info.orig_filename.endswith(f".{ext}") for ext in JAR_SBF_EXTS):
            if f"{base}.SF" not in filenames:
                return f"signature file missing for {info.orig_filename!r}"
    if len(filenames) == 1 and output_zf:
        for info in output_zf.infolist():
            if info.orig_filename == JAR_MANIFEST and output_zf.read(info) != datas[JAR_MANIFEST]:
                return "manifest data mismatch"
    if len(filenames) > MAX_SIGNERS * 2 + 1:
        return "too many signers"
    return None


# NB: superseded by the new extract_v1_sig() format
def extract_meta(signed_apk: str, *, strict: bool = True) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    r"""
    Extract legacy v1 signature metadata files from signed APK.

    Yields (ZipInfo, data) pairs.

    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(extract_meta(apk))
    >>> [x.orig_filename for x, _ in meta]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> for line in meta[0][1].splitlines()[:4]:
    ...     print(line.decode())
    Signature-Version: 1.0
    Created-By: 1.0 (Android)
    SHA-256-Digest-Manifest: hz7AxDJU9Namxoou/kc4Z2GVRS9anCGI+M52tbCsXT0=
    X-Android-APK-Signed: 2, 3
    >>> for line in meta[2][1].splitlines()[:2]:
    ...     print(line.decode())
    Manifest-Version: 1.0
    Created-By: 1.8.0_45-internal (Oracle Corporation)

    """
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.orig_filename, strict=strict):
                yield info, zf_sig.read(info)


def extract_differences(signed_apk: str, extracted_meta: Optional[ZipInfoDataPairs]) \
        -> Optional[Dict[str, Any]]:
    r"""
    Extract ZIP metadata differences from signed APK.

    >>> import pprint
    >>> apk = "test/apks/apks/debuggable-boolean.apk"
    >>> meta = tuple(extract_meta(apk))
    >>> [x.orig_filename for x, _ in meta]
    ['META-INF/CERT.SF', 'META-INF/CERT.RSA', 'META-INF/MANIFEST.MF']
    >>> diff = extract_differences(apk, meta)
    >>> pprint.pprint(diff)
    {'files': {'META-INF/CERT.RSA': {'flag_bits': 2056},
               'META-INF/CERT.SF': {'flag_bits': 2056},
               'META-INF/MANIFEST.MF': {'flag_bits': 2056}}}

    >>> meta[2][0].extract_version = 42
    >>> try:
    ...     extract_differences(apk, meta)
    ... except ZipError as e:
    ...     print(e)
    Unsupported extract_version

    >>> validate_differences(diff) is None
    True
    >>> diff["files"]["META-INF/OOPS"] = {}
    >>> validate_differences(diff)
    ".files key 'META-INF/OOPS' is not a metadata file"
    >>> del diff["files"]["META-INF/OOPS"]
    >>> diff["files"]["META-INF/CERT.RSA"]["compresslevel"] = 42
    >>> validate_differences(diff)
    ".files['META-INF/CERT.RSA'].compresslevel has an unexpected value"
    >>> diff["oops"] = 42
    >>> validate_differences(diff)
    'contains unknown key(s)'

    """
    differences: Dict[str, Any] = {}
    files = {}
    for info, data in (extracted_meta or ()):
        diffs = {}
        for k in VALID_ZIP_META:
            if k != "compresslevel":
                v = getattr(info, k)
                if v != APKZipInfo._override[k]:
                    if v not in VALID_ZIP_META[k]:
                        raise ZipError(f"Unsupported {k}")
                    diffs[k] = v
        level = _get_compresslevel(signed_apk, info, data)
        if level != APKZipInfo.COMPRESSLEVEL:
            diffs["compresslevel"] = level
        if diffs:
            files[info.orig_filename] = diffs
    if files:
        differences["files"] = files
    if zfe_size := detect_zfe(signed_apk):
        differences["zipflinger_virtual_entry"] = zfe_size
    return differences or None


def validate_differences(differences: Dict[str, Any]) -> Optional[str]:
    """
    Validate differences dict.

    Returns None if valid, error otherwise.
    """
    if set(differences) - {"files", "zipflinger_virtual_entry"}:
        return "contains unknown key(s)"
    if "zipflinger_virtual_entry" in differences:
        if type(differences["zipflinger_virtual_entry"]) is not int:
            return ".zipflinger_virtual_entry is not an int"
        if not (30 <= differences["zipflinger_virtual_entry"] <= 4096):
            return ".zipflinger_virtual_entry is < 30 or > 4096"
    if "files" in differences:
        if not isinstance(differences["files"], dict):
            return ".files is not a dict"
        for name, info in differences["files"].items():
            if not is_meta(name, strict=True):
                return f".files key {name!r} is not a metadata file"
            if not isinstance(info, dict):
                return f".files[{name!r}] is not a dict"
            if set(info) - set(VALID_ZIP_META):
                return f".files[{name!r}] contains unknown key(s)"
            for k, v in info.items():
                if v not in VALID_ZIP_META[k]:
                    return f".files[{name!r}].{k} has an unexpected value"
    return None


def _get_compresslevel(apkfile: str, info: zipfile.ZipInfo, data: bytes) -> int:
    if info.compress_type != 8:
        raise ZipError("Unsupported compress_type")
    crc = _get_compressed_crc(apkfile, info)
    for level in VALID_ZIP_META["compresslevel"]:
        comp = zlib.compressobj(level, 8, -15)
        if zlib.crc32(comp.compress(data) + comp.flush()) == crc:
            return level
    raise ZipError("Unsupported compresslevel")


def _get_compressed_crc(apkfile: str, info: zipfile.ZipInfo) -> int:
    with open(apkfile, "rb") as fh:
        fh.seek(info.header_offset)
        hdr = fh.read(30)
        if hdr[:4] != b"\x50\x4b\x03\x04":
            raise ZipError("Expected local file header signature")
        n, m = struct.unpack("<HH", hdr[26:30])
        fh.seek(n + m, os.SEEK_CUR)
        return zlib.crc32(fh.read(info.compress_size))


# NB: superseded by the new extract_v1_sig() format
def patch_meta(extracted_meta: ZipInfoDataPairs, output_apk: str,
               date_time: DateTime = DATETIMEZERO, *,
               differences: Optional[Dict[str, Any]] = None) -> None:
    r"""
    Add legacy v1 signature metadata to APK (removes v2 sig block, if any).

    >>> unsigned_apk = "test/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(extract_meta(signed_apk))
    >>> [x.orig_filename for x, _ in meta]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> with zipfile.ZipFile(unsigned_apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     copy_apk(unsigned_apk, out)
    ...     patch_meta(meta, out)
    ...     with zipfile.ZipFile(out, "r") as zf:
    ...         infos_out = zf.infolist()
    (2017, 5, 15, 11, 28, 40)
    >>> for i in infos_in:
    ...     print(i.orig_filename)
    META-INF/
    META-INF/MANIFEST.MF
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> for i in infos_out:
    ...     print(i.orig_filename)
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    META-INF/RSA-2048.SF
    META-INF/RSA-2048.RSA
    META-INF/MANIFEST.MF

    """
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        for info in zf_out.infolist():
            if is_meta(info.orig_filename) or is_meta(info.orig_filename.split("\x00", 1)[0]):
                raise ZipError("Unexpected metadata")
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        for info, data in extracted_meta:
            if differences and "files" in differences:
                more = differences["files"].get(info.orig_filename, {}).copy()
            else:
                more = {}
            level = more.pop("compresslevel", APKZipInfo.COMPRESSLEVEL)
            zinfo = APKZipInfo(info, date_time=date_time, **more)
            zf_out.writestr(zinfo, data, compresslevel=level)


def extract_v2_sig(apkfile: str, expected: bool = True) -> Optional[Tuple[int, bytes]]:
    r"""
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    NoAPKSigningBlock when expected is True, else returns None.

    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> sb_offset, sig_block = extract_v2_sig(apk)
    >>> sb_offset
    8192
    >>> len(sig_block)
    4096

    >>> apk = "test/apks/apks/golden-aligned-in.apk"
    >>> try:
    ...     extract_v2_sig(apk)
    ... except NoAPKSigningBlock as e:
    ...     print(e)
    No APK Signing Block

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


def zip_data(apkfile: str, count: int = 65536) -> ZipData:
    r"""
    Extract central directory, EOCD, and offsets from ZIP.

    Returns ZipData.

    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> data = zip_data(apk)
    >>> data.cd_offset, data.eocd_offset
    (12288, 12843)
    >>> len(data.cd_and_eocd)
    577

    """
    with open(apkfile, "rb") as fh:
        return _zip_data(fh, count=min(os.path.getsize(apkfile), count))


def _zip_data(fh: BinaryIO, count: int = 65536) -> ZipData:
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
    r"""
    Implant extracted v2/v3 signature into APK.

    >>> unsigned_apk = "test/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> v2_sig = extract_v2_sig(signed_apk)
    >>> meta = tuple(extract_meta(signed_apk))
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     date_time = copy_apk(unsigned_apk, out)
    ...     patch_meta(meta, out, date_time=date_time)              # legacy format
    ...     extract_v2_sig(out, expected=False) is None
    ...     patch_v2_sig(v2_sig, out)
    ...     extract_v2_sig(out) == v2_sig
    ...     with open(signed_apk, "rb") as a, open(out, "rb") as b:
    ...         a.read() == b.read()
    True
    True
    True
    >>> v1_sig = extract_v1_sig(signed_apk)
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     date_time = copy_apk(unsigned_apk, out, v1_sig=v1_sig)  # new format
    ...     extract_v2_sig(out, expected=False) is None
    ...     patch_v2_sig(v2_sig, out)
    ...     extract_v2_sig(out) == v2_sig
    ...     with open(signed_apk, "rb") as a, open(out, "rb") as b:
    ...         a.read() == b.read()
    True
    True
    True

    """
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(output_apk)
    len_padding = signed_sb_offset - data_out.cd_offset
    if len_padding < 0:
        raise APKSigningBlockError("APK Signing Block offset < central directory offset")
    if len_padding > 65536:
        raise APKSigningBlockError("APK Signing Block offset requires more than 64k padding")
    padding = b"\x00" * len_padding
    offset = len(signed_sb) + len_padding
    with open(output_apk, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


def patch_apk(extracted_meta: Union[ZipInfoDataPairs, bytes, None],
              extracted_v2_sig: Optional[Tuple[int, bytes]],
              unsigned_apk: str, output_apk: str, *,
              differences: Optional[Dict[str, Any]] = None,
              exclude: Optional[Callable[[str], bool]] = None,
              v1_sig: Optional[bytes] = None) -> None:
    """
    Patch extracted_meta/v1_sig + extracted_v2_sig (if not None) onto
    unsigned_apk and save as output_apk.

    NB: extracted_meta as ZipInfoDataPairs uses the legacy v1 signature files
    format returned by extract_meta(), which has been superseded by the ZIP file
    data returned by extract_v1_sig() as a bytes object; for backwards
    compatibility, the mandatory extracted_meta parameter was kept as-is, though
    it can now be None or a bytes object, and the optional keyword-only v1_sig
    parameter added as a more explicit way to use the new format (in which case
    extracted_meta must be None).
    """
    if extracted_meta and v1_sig:
        raise ValueError("Expected either extracted_meta or v1_sig, not both")
    if isinstance(extracted_meta, bytes):
        v1_sig, extracted_meta = extracted_meta, None
    if differences and "zipflinger_virtual_entry" in differences:
        zfe_size = differences["zipflinger_virtual_entry"]
    else:
        zfe_size = None
    date_time = copy_apk(unsigned_apk, output_apk, exclude=exclude, zfe_size=zfe_size, v1_sig=v1_sig)
    if extracted_meta:
        patch_meta(extracted_meta, output_apk, date_time=date_time, differences=differences)
    if extracted_v2_sig:
        patch_v2_sig(extracted_v2_sig, output_apk)


def verify_apk(apk: str, min_sdk_version: Optional[int] = None,
               verify_cmd: Optional[Tuple[str, ...]] = None) -> None:
    """Verifies APK using apksigner."""
    args = tuple(verify_cmd or VERIFY_CMD)
    if min_sdk_version is not None:
        args += (f"--min-sdk-version={min_sdk_version}",)
    args += ("--", apk)
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise APKSigCopierError(f"failed to verify {apk}")          # pylint: disable=W0707
    except FileNotFoundError:
        raise APKSigCopierError(f"{args[0]} command not found")     # pylint: disable=W0707


def sha256_file(filename: str) -> str:
    r"""
    Calculate SHA-256 checksum of file.

    >>> sha256_file("/dev/null")
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    >>> sha256_file("test/apks/apks/golden-aligned-in.apk")
    '0e896ce038fb093e1342f65e815ffe45c121ea0a61ebc46bdc48b775866a6185'
    >>> sha256_file("test/apks/apks/golden-aligned-v1v2v3-out.apk")
    'ba7828ba42a3b68bd3acff78773e41d6a62aabe6317538671441c568748d9cd7'

    """
    with open(filename, "rb") as fh:
        sha = hashlib.sha256()
        while chunk := fh.read(4096):
            sha.update(chunk)
        return sha.hexdigest()


def has_v1_signature(apkfile: str) -> bool:
    r"""
    Check for signature (block) files indicating a v1 signature.

    NB: intentionally skips MANIFEST.MF and returns True for unpaired files!

    >>> has_v1_signature("test/apks/apks/golden-aligned-in.apk")
    False
    >>> has_v1_signature("test/apks/apks/golden-aligned-v1v2v3-out.apk")
    True
    >>> has_v1_signature("test/apks/apks/golden-aligned-v2v3-out.apk")
    False
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     with zipfile.ZipFile(out, "w") as zf:
    ...         zf.writestr(JAR_MANIFEST, "")
    ...     has_v1_signature(out)
    ...     with zipfile.ZipFile(out, "w") as zf:
    ...         zf.writestr("META-INF/CERT.SF", "")
    ...     has_v1_signature(out)
    False
    True

    """
    with zipfile.ZipFile(apkfile, "r") as zf:
        infos = zf.infolist()
    return any(is_meta(info.orig_filename) and info.orig_filename != JAR_MANIFEST for info in infos)


# FIXME: support multiple signers?
def do_extract(signed_apk: str, output_dir: str, v1_only: NoAutoYesBoolNone = NO,
               *, ignore_differences: bool = False, legacy: Optional[bool] = None) -> None:
    """
    Extract signatures from signed_apk and save in output_dir.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    if legacy is None:
        legacy = legacy_v1sigfile
    v1_only = noautoyes(v1_only)
    v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO) if v1_only != YES else None
    if legacy:
        extracted_meta, v1_sig = tuple(extract_meta(signed_apk)), None
        if len(extracted_meta) not in (len(META_EXT), 0):
            raise APKSigCopierError("Unexpected or missing metadata files in signed_apk")
        for info, data in extracted_meta:
            name = os.path.basename(info.orig_filename)
            with open(os.path.join(output_dir, name), "wb") as fh:
                fh.write(data)
    else:
        extracted_meta, v1_sig = None, extract_v1_sig(signed_apk)
        if v1_sig:
            with open(os.path.join(output_dir, V1SIGZIP), "wb") as fh:
                fh.write(v1_sig)
    if not v2_sig:
        if not (extracted_meta or v1_sig):
            what = "v1 signature" if v1_only == YES else "v1 and/or v2/v3 signature, found neither"
            raise APKSigCopierError(f"Expected {what}")
        return
    signed_sb_offset, signed_sb = v2_sig
    with open(os.path.join(output_dir, SIGOFFSET), "w", encoding="utf-8") as fh:
        fh.write(str(signed_sb_offset) + "\n")
    with open(os.path.join(output_dir, SIGBLOCK), "wb") as fh:
        fh.write(signed_sb)
    if not (ignore_differences or v1_sig):
        if differences := extract_differences(signed_apk, extracted_meta):
            with open(os.path.join(output_dir, DIFF_JSON), "w", encoding="utf-8") as fh:
                json.dump(differences, fh, sort_keys=True, indent=2)
                fh.write("\n")


# FIXME: support multiple signers?
def do_patch(metadata_dir: str, unsigned_apk: str, output_apk: str,
             v1_only: NoAutoYesBoolNone = NO, *,
             exclude: Optional[Callable[[str], bool]] = None,
             ignore_differences: bool = False) -> None:
    """
    Patch signatures from metadata_dir onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta, differences, v1_sig = [], None, None
    v1_sig_file = os.path.join(metadata_dir, V1SIGZIP)
    if os.path.exists(v1_sig_file):
        with open(v1_sig_file, "rb") as fh:
            v1_sig = fh.read()
    for pat in META_EXT:
        files = [fn for ext in pat.split("|") for fn in
                 glob.glob(os.path.join(metadata_dir, "*." + ext))]
        if len(files) != 1:
            continue
        info = zipfile.ZipInfo("META-INF/" + os.path.basename(files[0]))
        with open(files[0], "rb") as fh:
            extracted_meta.append((info, fh.read()))
    if len(extracted_meta) not in (len(META_EXT), 0) or (extracted_meta and v1_sig):
        raise APKSigCopierError("Unexpected or missing files in metadata_dir")
    if v1_only == YES:
        v2_sig = None
    else:
        sigoffset_file = os.path.join(metadata_dir, SIGOFFSET)
        sigblock_file = os.path.join(metadata_dir, SIGBLOCK)
        if not os.path.exists(sigblock_file):
            if v1_only == NO:
                raise APKSigCopierError("Expected v2/v3 signature")
            v2_sig = None
        else:
            with open(sigoffset_file, "r", encoding="utf-8") as fh:
                signed_sb_offset = int(fh.read())
            with open(sigblock_file, "rb") as fh:
                signed_sb = fh.read()
            v2_sig = signed_sb_offset, signed_sb
            differences_file = os.path.join(metadata_dir, DIFF_JSON)
            if not ignore_differences and os.path.exists(differences_file):
                with open(differences_file, "r", encoding="utf-8") as fh:
                    try:
                        differences = json.load(fh)
                    except json.JSONDecodeError as e:
                        raise APKSigCopierError(f"Invalid {DIFF_JSON}: {e}")    # pylint: disable=W0707
                    if error := validate_differences(differences):
                        raise APKSigCopierError(f"Invalid {DIFF_JSON}: {error}")
    if not (extracted_meta or v1_sig) and not v2_sig:
        what = "v1 signature" if v1_only == YES else "v1 and/or v2/v3 signature, found neither"
        raise APKSigCopierError(f"Expected {what}")
    patch_apk(extracted_meta, v2_sig, unsigned_apk, output_apk, differences=differences,
              exclude=exclude, v1_sig=v1_sig)


def do_copy(signed_apk: str, unsigned_apk: str, output_apk: str,
            v1_only: NoAutoYesBoolNone = NO, *,
            exclude: Optional[Callable[[str], bool]] = None,
            ignore_differences: bool = False, legacy: Optional[bool] = None) -> None:
    """
    Copy signatures from signed_apk onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    if legacy is None:
        legacy = legacy_v1sigfile
    v1_only = noautoyes(v1_only)
    v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO) if v1_only != YES else None
    if legacy:
        extracted_meta, v1_sig = tuple(extract_meta(signed_apk)), None
    else:
        extracted_meta, v1_sig = None, extract_v1_sig(signed_apk)
    if v2_sig and not (ignore_differences or v1_sig):
        differences = extract_differences(signed_apk, extracted_meta)
    else:
        differences = None
    patch_apk(extracted_meta, v2_sig, unsigned_apk, output_apk, differences=differences,
              exclude=exclude, v1_sig=v1_sig)


def do_compare(first_apk: str, second_apk: str, unsigned: bool = False,
               min_sdk_version: Optional[int] = None, *,
               check_signature: bool = True, check_sha256: bool = True,
               ignore_differences: bool = False, legacy: Optional[bool] = None,
               verify_cmd: Optional[Tuple[str, ...]] = None) -> None:
    r"""
    Compare first_apk to second_apk by:
    * using apksigner to check if the first APK verifies
    * checking if the second APK also verifies (unless unsigned is True)
    * copying the signature from first_apk to a copy of second_apk
    * checking if the resulting APK verifies
    * checking if the SHA-256 hash of the resulting APK is identical to that of the original

    You can disable the apksigner signature verification and SHA-256 checks (but
    not both) by setting check_signature=False or check_sha256=False,
    respectively; disabling the SHA-256 check will still print a warning on
    mismatch.

    >>> first_apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> second_apk = "test/apks/apks/golden-aligned-in.apk"
    >>> do_compare(first_apk, second_apk, unsigned=True, check_signature=False)
    >>> try:
    ...     do_compare(first_apk, "test/apks/apks/debuggable-boolean.apk", check_signature=False)
    ... except APKSigCopierError as e:
    ...     print(e)
    SHA-256 mismatch: expected 'ba7828ba42a3b68bd3acff78773e41d6a62aabe6317538671441c568748d9cd7', actual '506ced930918475beb19d003206b6c1a77ff5b67bbe6c4fa47dac648ee615e16'

    """
    if not (check_signature or check_sha256):
        raise ValueError("Expected either check_signature or check_sha256")
    sha256_first = sha256_file(first_apk)
    if check_signature:
        verify_apk(first_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
        if not unsigned:
            verify_apk(second_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
    with tempfile.TemporaryDirectory() as tmpdir:
        output_apk = os.path.join(tmpdir, "output.apk")        # FIXME
        exclude = exclude_default if unsigned else exclude_meta
        do_copy(first_apk, second_apk, output_apk, v1_only=AUTO, exclude=exclude,
                ignore_differences=ignore_differences, legacy=legacy)
        if check_signature:
            min_sdk_version = 23 if has_v1_signature(output_apk) else 24
            verify_apk(output_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
        sha256_output = sha256_file(output_apk)
        if sha256_first != sha256_output:
            error = f"SHA-256 mismatch: expected {sha256_first!r}, actual {sha256_output!r}"
            if check_sha256:
                raise APKSigCopierError(error)
            print(f"Warning: {error}.", file=sys.stderr)


def main() -> None:
    """CLI; requires click."""

    global exclude_all_meta, copy_extra_bytes, skip_realignment, legacy_v1sigfile
    exclude_all_meta = os.environ.get("APKSIGCOPIER_EXCLUDE_ALL_META") in ("1", "yes", "true")
    copy_extra_bytes = os.environ.get("APKSIGCOPIER_COPY_EXTRA_BYTES") in ("1", "yes", "true")
    skip_realignment = os.environ.get("APKSIGCOPIER_SKIP_REALIGNMENT") in ("1", "yes", "true")
    legacy_v1sigfile = os.environ.get("APKSIGCOPIER_LEGACY_V1SIGFILE") in ("1", "yes", "true")

    import click

    NAY = click.Choice(NOAUTOYES)

    @click.group(help="""
        apksigcopier - copy/extract/patch android apk signatures & compare apks
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.command(help="""
        Extract APK signatures from signed APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help=f"Don't write {DIFF_JSON}.")
    @click.option("--legacy/--no-legacy", default=None,
                  help="Use the legacy v1 signature files format.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
    def extract(*args: Any, **kwargs: Any) -> None:
        do_extract(*args, **kwargs)

    @cli.command(help="""
        Patch extracted APK signatures onto unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help=f"Don't read {DIFF_JSON}.")
    @click.argument("metadata_dir", type=click.Path(exists=True, file_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def patch(*args: Any, **kwargs: Any) -> None:
        do_patch(*args, **kwargs)

    @cli.command(help="""
        Copy (extract & patch) signatures from signed to unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help="Don't copy metadata differences.")
    @click.option("--legacy/--no-legacy", default=None,
                  help="Use the legacy v1 signature files format.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def copy(*args: Any, **kwargs: Any) -> None:
        do_copy(*args, **kwargs)

    @cli.command(help="""
        Compare two APKs by copying the signature from the first to a copy of
        the second and checking if the resulting APK verifies.  Also checks if
        the SHA-256 hash of the resulting APK is identical to that of the
        original (only warns when --no-check-sha256 is used).

        This command requires apksigner (unless --no-check-signature is used).
    """)
    @click.option("--no-check-signature", "check_signature", flag_value=False, default=True,
                  help="Don't verify signature with apksigner.")
    @click.option("--no-check-sha256", "check_sha256", flag_value=False, default=True,
                  help="Don't check for identical SHA-256.")
    @click.option("--unsigned", is_flag=True, help="Accept unsigned SECOND_APK.")
    @click.option("--min-sdk-version", type=click.INT, help="Passed to apksigner.")
    @click.option("--ignore-differences", is_flag=True, help="Don't copy metadata differences.")
    @click.option("--legacy/--no-legacy", default=None,
                  help="Use the legacy v1 signature files format.")
    @click.option("--verify-cmd", metavar="COMMAND", help="Command (with arguments) used to "
                  f"verify APKs.  [default: {' '.join(VERIFY_CMD)!r}]")
    @click.argument("first_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("second_apk", type=click.Path(exists=True, dir_okay=False))
    @click.pass_context
    def compare(ctx: click.Context, /, *args: Any, **kwargs: Any) -> None:
        if not (kwargs["check_signature"] or kwargs["check_sha256"]):
            raise click.exceptions.BadParameter(
                "Conflicting options: --no-check-signature and --no-check-sha256", ctx)
        if kwargs["verify_cmd"] is not None:
            kwargs["verify_cmd"] = tuple(kwargs["verify_cmd"].split())
        do_compare(*args, **kwargs)

    try:
        cli(prog_name=NAME)
    except (APKSigCopierError, zipfile.BadZipFile) as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
