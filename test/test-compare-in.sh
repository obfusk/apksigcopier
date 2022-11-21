#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/apks/golden-aligned-*out.apk; do
  echo "$apk"
  if unzip -l "$apk" 2>/dev/null | grep -qF META-INF/MANIFEST.MF; then
    min=
  else
    min=--min-sdk-version=24
  fi
  apksigcopier compare $min "$apk" --unsigned apks/apks/golden-aligned-in.apk
done
