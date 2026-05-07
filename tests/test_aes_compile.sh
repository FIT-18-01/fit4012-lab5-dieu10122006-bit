#!/usr/bin/env bash
set -euo pipefail

g++ -std=c++17 -Wall -Wextra -pedantic encrypt.cpp -o encrypt
g++ -std=c++17 -Wall -Wextra -pedantic decrypt.cpp -o decrypt

[[ -x ./encrypt ]] || { echo "[FAIL] Missing encrypt executable"; exit 1; }
[[ -x ./decrypt ]] || { echo "[FAIL] Missing decrypt executable"; exit 1; }

echo "[PASS] AES encrypt/decrypt programs compile successfully."
