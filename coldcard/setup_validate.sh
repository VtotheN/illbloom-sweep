#!/bin/bash
# setup_validate.sh — ejecutar al SSH conectar al pod. Valida sweeper BIP39 + GPU lista.
set -x
cd /root
echo "=== GPU ==="; nvidia-smi -L 2>/dev/null; echo "cores=$(nproc)"; git --version; gcc --version | head -1
echo "=== deps ==="
apt-get update -qq && apt-get install -y -qq libsecp256k1-dev libssl-dev 2>&1 | tail -2
echo "=== clone + build ==="
git clone --depth 1 https://github.com/VtotheN/illbloom-sweep.git /work 2>/dev/null
cd /work/coldcard
gcc -O3 -pthread -o yas yasmarang_sweep.c pbkdf2.c hmac.c sha2.c sha3.c ripemd160.c memzero.c -lcrypto -lsecp256k1 -lpthread 2>&1 | grep -iE "error|undefined" || echo "BUILD OK"
echo "=== validar BIP84-24 sub-rango (mode 2): pad 0-65536 x TR 0-5 x SSR 0-16 ==="
timeout 300 ./yas 0 65536 5 16 oracle.bin 2 2>&1 | grep -E "HIT|DONE|oracle" | head
echo "=== si BUILD OK + produce addresses, GPU lista para escribir CUDA ==="
nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader
