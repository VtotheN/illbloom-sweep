#!/bin/bash
# run_pod.sh — start script del pod RunPod RTX 4090.
# Corre yasmarang_sweep paper mode 2^32 sharded por nproc cores (CPU-binario, rapido).
# Output: HIT lines en hit_*.txt. CUDA/BIP39 se agrega despues.
set -e
cd /root
export DEBIAN_FRONTEND=noninteractive
echo "=== setup ==="
apt-get update -qq && apt-get install -y -qq libsecp256k1-dev libssl-dev git gcc make > /dev/null 2>&1
git clone --depth 1 https://github.com/VtotheN/illbloom-sweep /work 2>/dev/null || true
cd /work/coldcard
echo "=== build ==="
gcc -O3 -pthread -o yas yasmarang_sweep.c pbkdf2.c hmac.c sha2.c sha3.c ripemd160.c memzero.c \
    -lcrypto -lsecp256k1 -lpthread 2>&1 | grep -i error || echo "build OK"
N=$(nproc)
TOTAL=4294967296   # 2^32
CHUNK=$((TOTAL/N))
echo "=== paper 2^32 sweep, $N cores, chunk=$CHUNK ==="
date -u +%H:%M:%S
PIDS=""
for i in $(seq 0 $((N-1))); do
    S=$((i*CHUNK)); E=$((S+CHUNK))
    if [ $i -eq $((N-1)) ]; then E=$TOTAL; fi
    ./yas $S $E 0 0 oracle.bin 0 > hit_$i.txt 2> err_$i.txt &
    PIDS="$PIDS $!"
done
wait
date -u +%H:%M:%S
echo "=== RESULT ==="
HITS=$(cat hit_*.txt 2>/dev/null | grep "^HIT")
if [ -n "$HITS" ]; then
    echo "JACKPOT:"
    echo "$HITS"
else
    echo "0 HIT en paper 2^32 (RTC=0)"
    echo "checked total:"; cat err_*.txt | grep DONE | head
fi
echo "=== ready for CUDA/BIP39 ==="
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo "GPU check"
