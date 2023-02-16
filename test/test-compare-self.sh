#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *weird-compression-method* ]] || continue
  echo "$apk"
  if unzip -l "$apk" 2>/dev/null | grep -qF META-INF/MANIFEST.MF; then
    min=
  else
    min=--min-sdk-version=24
  fi
  if apksigner verify $min "$apk" >/dev/null 2>&1; then
    echo 'apksigner: verified'
    if apksigcopier compare $min "$apk" "$apk" 2>&1; then
      echo 'apksigcopier: success'
    else
      echo 'apksigcopier: failure'
    fi
  else
    echo 'apksigner: not verified'
  fi
  echo
done
