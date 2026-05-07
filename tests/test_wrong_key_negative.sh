#!/usr/bin/env bash
set -euo pipefail

make all >/dev/null
cat > keyfile <<'KEY'
01 04 02 03 01 03 04 0A 09 0B 07 0F 0F 06 03 00
KEY

PLAINTEXT="wrong key negative test"
printf "%s\n" "$PLAINTEXT" | ./encrypt >/tmp/aes_encrypt_wrong_key.log

# Wrong key / khóa sai.
cat > keyfile <<'KEY'
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
KEY

OUTPUT=$(./decrypt 2>&1 | tr -d '\000' || true)

if grep -q "$PLAINTEXT" <<< "$OUTPUT"; then
  echo "--- decrypt output ---"
  echo "$OUTPUT"
  echo "----------------------"
  echo "[FAIL] Wrong key should not recover original plaintext."
  exit 1
fi

echo "[PASS] Wrong key / khóa sai negative test changes decrypted output."
