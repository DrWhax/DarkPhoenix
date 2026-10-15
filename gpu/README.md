# DarkPhoenix on Metal

Native port of the [DarkPhoenix](../README.md) DFA attack against AES white-boxes with external encodings. The encoded white-box and the million-scale fault search run on the Apple GPU through Metal. The host is Swift, not Python, and the Sage step (8×8 similarity over GF(2)) is done with a small native solver.

This attacks the same white-box model as `darkphoenixAES.test.AESEncoded`: AES-128/192/256, byte-wise encodings between rounds, and an XOR fault in the encoded state. It recovers the cipher key and checks the external input/output encodings.

## Build

Requires Xcode with the macOS 27 SDK and the Metal toolchain (`xcodebuild -downloadComponent MetalToolchain` if `metal` is missing).

```bash
cd gpu
make
./darkphoenix-metal --selftest
```

`Shaders.metal` is compiled at runtime and must sit next to the binary (or pass `DARKPHOENIX_SHADER`).

## External oracle

The attack math stays in this process. `apply`, `applyFault`, and `applyReverse` are performed by another program. That program can be your existing `WhiteBoxedAES` subclass.

```bash
# reference oracle: the Python encoded-AES test white-box
PYTHONPATH=.. python3 -u oracle.py encoded --key 000102030405060708090a0b0c0d0e0f --seed 1

# from gpu/
./darkphoenix-metal --encodings --oracle \n  'python3 -u oracle.py encoded --key 000102030405060708090a0b0c0d0e0f --seed 1'
```

To wrap your own class, either pass `class module:ClassName --json '{...}'`, or call `serve(wb)` yourself:

```python
import sys
sys.path.insert(0, "gpu")
from oracle import serve

class MyWhiteBoxedAES(WhiteBoxedAES):
    def apply(self, data): ...
    def applyFault(self, data, faults):
        fround, fbytes, fxorval = faults[0]
        ...

serve(MyWhiteBoxedAES(...))
```

```bash
./darkphoenix-metal --oracle 'python3 -u my_oracle.py' --encodings

# unknown fault sites: the class must inherit WhiteBoxedAESAuto
./darkphoenix-metal --auto --oracle 'python3 -u oracle.py encoded --auto --key HEX --seed 1'

# resume a long run
./darkphoenix-metal --backup attack.json --oracle 'python3 -u my_oracle.py'
```

Round keys are printed as `kNN`. `--force-offset N` overrides the round used to revert the key. `--partial` stops step 5 after one round (AES-128) or two (AES-192/256). `--no-progress` quiets the step log. `--retry N` caps `--auto` retries (`-1` means keep going). `getRandomInput` and `newThread` are called when the class defines them. `prepareFaultPosition` is called for `WhiteBoxedAESDynamic`, with the reverse-round callbacks the Python tool passes.

Do not write to stdout from the oracle; the protocol owns it. Prints are redirected to stderr. Fault indexes are the same contract as the Python tool: 16 stable byte labels per round, one XOR fault per call. If `hasReverse()` is false, pass `--no-reverse` (or it is selected automatically and step 1 searches). A slow oracle dominates runtime: step 2 is 1,048,576 faulted queries, sent in batches of 2048.

## Run

```bash
# random AES-128 white-box, recover the key
./darkphoenix-metal --seed 7

# known key, also check external encodings
./darkphoenix-metal --key 000102030405060708090a0b0c0d0e0f --seed 7 --encodings

# no inverse oracle: step 1 is a GPU search instead of 510 decryptions
./darkphoenix-metal --no-reverse --seed 11

# AES-256 decrypt
./darkphoenix-metal --bits 256 --decrypt --seed 23

# paper's two-fixed-byte step 1 (about 100× more encryptions)
./darkphoenix-metal --no-reverse --double --identity --seed 1

# throughput of the faulted white-box
./darkphoenix-metal --bench 1048576
```

`--cpu` runs the same attack with an ARM AES/NEON C kernel called from Swift. It uses the CPU's AES instructions for the rounds and table lookups for the byte encodings. GPU results are checked against this CPU implementation.

## What runs where

| Work | Where |
| --- | --- |
| Faulted / plain encoded AES (steps 1–5) | Metal compute kernels, or ARM AES/NEON with `--cpu` |
| Step 1 search when the white-box has no inverse | Metal, atomic slot fill; CPU search with `--cpu` |
| Tolhuizen, meet-in-the-middle, key schedule | Swift |
| Step 3.2 matrix identification (was Sage) | Swift GF(2) linear algebra |

A white-box that is an external process (debugger, remote oracle) is still limited by that oracle. This port is the in-process attack: the white-box itself is the GPU kernel.

## Measured on this machine

Apple M5 Pro, 16 GPU cores, macOS 27.0.1. Rerun on 2026-10-15 with the optimized `make` build. Values are medians of seven runs after one discarded warm-up per case, with CPU and GPU recovery runs interleaved.

Full key recovery with random encodings (`--seed 7 --encodings`), including external-encoding recovery and verification:

| Case | Metal | CPU ARM AES/NEON |
| --- | ---: | ---: |
| AES-128 encrypt, inverse available | 121.1 ms | 66.4 ms |
| AES-128 encrypt, no inverse (step 1 search) | 119.7 ms | 100.8 ms |
| AES-128 decrypt, inverse available | 103.8 ms | 49.4 ms |
| AES-256 encrypt, inverse available | 129.1 ms | 67.9 ms |

These are the program's `total` timings, which exclude process startup, white-box initialization, and Metal setup/oracle checks. For AES-128 encrypt with an inverse, median process wall time was 165.5 ms on Metal and 72.3 ms on CPU. The accelerated CPU is about **1.8× faster** for this full recovery.

Faulted AES-128 throughput (`--bench 1048576`, identity encodings, batches of 65,536):

| Backend | Throughput |
| --- | ---: |
| Metal | 75.50 M blocks/s |
| CPU ARM AES/NEON | 54.39 M blocks/s |

`--bench` reports both backends and includes Swift job construction and dispatch overhead. It uses identity encodings regardless of other flags. Metal is about **1.4× faster** in this benchmark.

Step 2 uses a specialized batch path, so its time should not be inferred from `--bench`. For the AES-128 encrypt recovery with an inverse and random encodings, measured step 2 time was **9.4 ms on Metal** and **7.8 ms on CPU** for 1,048,576 faulted outputs, including result processing. The CPU kernel reuses the prefix before the fault across XOR values.

To repeat the recovery cases, run each command with and without `--cpu`:

```bash
./darkphoenix-metal --seed 7 --encodings
./darkphoenix-metal --seed 7 --encodings --no-reverse
./darkphoenix-metal --seed 7 --encodings --decrypt
./darkphoenix-metal --seed 7 --encodings --bits 256
./darkphoenix-metal --bench 1048576
```

The earlier CPython + `cryptography` `WhiteBoxedAESTest` measurement was 0.029 M faulted blocks/s (about 36 s for 1,048,576 calls). This historical baseline was not rerun: the available Python environments lack `tqdm`. The Python tool also needs Sage for step 3; this port does not.
