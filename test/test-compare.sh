#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *weird-compression-method* ]] || continue
  echo "$apk"
  if apksigner verify --min-sdk-version=28 "$apk" >/dev/null 2>&1; then
    echo 'apksigner: verified'
    if apksigcopier compare --min-sdk-version=28 "$apk" "$apk" 2>&1; then
      echo 'apksigcopier: success'
    else
      echo 'apksigcopier: failure'
    fi
  else
    echo 'apksigner: not verified'
  fi
  echo
done
