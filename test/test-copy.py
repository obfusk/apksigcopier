#!/usr/bin/python3
# encoding: utf-8

import glob
import hashlib
import os
import tempfile
import zipfile

import apksigcopier

# NB: we want to test whether copying a signed APK is idempotent, so keep v1 signatures
apksigcopier.exclude_from_copying = lambda _: False


def shasum(filename):
    m = hashlib.sha256()
    with open(filename, "rb") as fh:
        while data := fh.read(4096):
            m.update(data)
    return m.hexdigest()


with tempfile.TemporaryDirectory() as tmpdir:
    output_apk = os.path.join(tmpdir, "output.apk")
    for apk in sorted(glob.glob("apks/*.apk")):
        if "empty" in apk:
            continue
        print(f"{apk}:")
        try:
            apksigcopier.copy_apk(apk, output_apk)
            extracted_v2_sig = apksigcopier.extract_v2_sig(apk, expected=False)
            if extracted_v2_sig is not None:
                apksigcopier.patch_v2_sig(extracted_v2_sig, output_apk)
        except (apksigcopier.APKSigCopierError, zipfile.BadZipFile) as e:
            print(f"copy failed: {e}")
        else:
            expected, got = shasum(apk), shasum(output_apk)
            if expected == got:
                print("checksum OK")
            else:
                print(f"checksum failed: expected {expected}, got {got}")
        print()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
