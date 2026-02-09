#!/usr/bin/env -S sage --python

from sage.all import Integer
from pwn import *

sock = remote("localhost", 8080)

line = sock.recvline_startswith(b"n:").decode()
n = int(line.split(" ")[1].strip())
[p, q] = [f for f, n in list(Integer(n).factor())]

sock.recvuntil(b"paillier> ")
sock.sendline(b"getflag\n")
ciphertext1 = sock.recvline_startswith(b"Encrypted flag 1 (weak): ").decode().split(" ")[-1].strip()

# with p, q, compute secrets
l = (p - 1)*(q-1)
n2 = pow(n, 2)
mu = pow(l, -1, n)
g = n + 1

def decrypt(c: int):
    return (((pow(c, l, n2) - 1) // n) * mu) % n

plaintext1 = decrypt(int(ciphertext1))
chars = [chr(d) for d in list(Integer(plaintext1).digits(256))]
chars.reverse()
answer = "".join(chars)

print(answer)