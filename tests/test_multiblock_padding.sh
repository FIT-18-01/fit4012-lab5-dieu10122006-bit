#!/usr/bin/env bash
set -euo pipefail

make all >/dev/null
cat > keyfile <<'KEY'
01 04 02 03 01 03 04 0A 09 0B 07 0F 0F 06 03 00
KEY

PLAINTEXT="AES message longer than one block"
printf "%s\n" "$PLAINTEXT" | ./encrypt >/tmp/aes_encrypt_multiblock.log
OUTPUT=$(./decrypt 2>&1 | tr -d '\000')

if ! grep -q "$PLAINTEXT" <<< "$OUTPUT"; then
  echo "--- decrypt output ---"
  echo "$OUTPUT"
  echo "----------------------"
  echo "[FAIL] Multi-block plaintext was not recovered."
  exit 1
fi

echo "[PASS] Multi-block plaintext with zero padding is recovered."
