#!/usr/bin/env bash
set -euo pipefail

make all >/dev/null
cat > keyfile <<'KEY'
01 04 02 03 01 03 04 0A 09 0B 07 0F 0F 06 03 00
KEY

PLAINTEXT="hello FIT4012 AES"
printf "%s\n" "$PLAINTEXT" | ./encrypt >/tmp/aes_encrypt_roundtrip.log
OUTPUT=$(./decrypt 2>&1 | tr -d '\000')

if ! grep -q "$PLAINTEXT" <<< "$OUTPUT"; then
  echo "--- decrypt output ---"
  echo "$OUTPUT"
  echo "----------------------"
  echo "[FAIL] Round-trip encrypt/decrypt did not recover plaintext."
  exit 1
fi

echo "[PASS] Round-trip encrypt/decrypt recovers plaintext."
