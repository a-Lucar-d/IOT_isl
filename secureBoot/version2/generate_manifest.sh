#!/bin/bash

MANIFEST="secureBoot.boot"
FILELIST="monitored_files.txt"

echo "[*] Generating manifest..."

> "$MANIFEST"

while read -r file
do
    if [ ! -f "$file" ]; then
        echo "[-] Missing file: $file"
        continue
    fi

    sha256sum "$file" >> "$MANIFEST"

done < "$FILELIST"

echo "[+] Manifest generated: $MANIFEST"
