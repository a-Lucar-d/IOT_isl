#!/bin/bash

MANIFEST="secureBoot.boot"
FILELIST="monitored_files.txt"

echo "[*] Generating manifest..."

if [ ! -f "$FILELIST" ]; then
    echo "[-] monitored_files.txt not found"
    exit 1
fi

sha256sum $(cat $FILELIST) > $MANIFEST

echo "[+] Manifest generated: $MANIFEST"
