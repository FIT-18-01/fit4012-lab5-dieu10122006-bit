#!/usr/bin/env bash
set -euo pipefail

make all >/dev/null
cat > keyfile <<'KEY'
01 04 02 03 01 03 04 0A 09 0B 07 0F 0F 06 03 00
KEY

PLAINTEXT="tamper negative test"
printf "%s\n" "$PLAINTEXT" | ./encrypt >/tmp/aes_encrypt_tamper.log

# Tamper / flip 1 byte in ciphertext.
python3 - <<'PY'
from pathlib import Path
p = Path('message.aes')
data = bytearray(p.read_bytes())
if not data:
    raise SystemExit('message.aes is empty')
data[0] ^= 0x01
p.write_bytes(data)
PY

OUTPUT=$(./decrypt 2>&1 | tr -d '\000' || true)

if grep -q "$PLAINTEXT" <<< "$OUTPUT"; then
  echo "--- decrypt output ---"
  echo "$OUTPUT"
  echo "----------------------"
  echo "[FAIL] Tamper / flip 1 byte should not recover original plaintext."
  exit 1
fi

echo "[PASS] Tamper / flip 1 byte negative test changes decrypted output."
