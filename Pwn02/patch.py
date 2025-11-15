#!/usr/bin/env python3
"""
Auto-patch for HackerShop challenge.

Usage:
    python3 patch.py chall chall_patched

Requires:
    pip install pwntools
"""

from pwn import *
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_binary> <output_binary>")
    sys.exit(1)

in_path  = sys.argv[1]
out_path = sys.argv[2]

context.arch = "amd64"
context.os   = "linux"

# Load ELF
elf = ELF(in_path, checksec=False)

# These offsets are from the decompiled code:
#   sub_113C  @ 0x113C  -> fish skill call
#   sub_14E3  @ 0x14E3  -> dog color handler (calls overflow)
#   sub_1583  @ 0x1583  -> system() wrapper
#   main      @ 0x1CC5  -> used to compute base
OFF_MAIN   = 0x1CC5
OFF_113C   = 0x113C
OFF_14E3   = 0x14E3
OFF_1583   = 0x1583

# Compute image base = real_main - 0x1CC5
try:
    real_main = elf.symbols["main"]
except KeyError:
    print("[!] Could not find symbol 'main' in ELF. Are you using the original chall binary?")
    sys.exit(1)

base = real_main - OFF_MAIN
log.info(f"Detected base: 0x{base:x}")

def patch_ret0(virt_addr, label):
    """
    Overwrite function entry at virt_addr with:

        xor eax, eax   ; return 0
        ret
    """
    stub = asm("xor eax, eax; ret")
    log.info(f"Patching {label} at 0x{virt_addr:x} with 'return 0'")
    elf.write(virt_addr, stub)

# Compute virtual addresses from offsets
addr_113C = base + OFF_113C
addr_14E3 = base + OFF_14E3
addr_1583 = base + OFF_1583

# 1) Disable fish skill indirect call (prevents arbitrary function calls)
patch_ret0(addr_113C, "sub_113C (fish skill call)")

# 2) Disable dog color change (removes heap overflow entirely)
patch_ret0(addr_14E3, "sub_14E3 (dog color handler)")

# 3) Disable system() wrapper (even if something still calls it)
patch_ret0(addr_1583, "sub_1583 (system wrapper)")

# Save patched binary
elf.save(out_path)
print(f"[+] Patched binary written to: {out_path}")


