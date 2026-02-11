#!/usr/bin/env python3

from sage.rings.factorint import factor_trial_division  # ty:ignore[unresolved-import]
from sage.all import Integer
from pwn import *

sock = remote("localhost", 8080)

sock.recvuntil(b"paillier> ")
sock.sendline(b"genkey strong")

line = sock.recvline_startswith(b"n:").decode()
n = int(line.split(" ")[1].strip())

# The paillier cryptosystems homomorphic property is the following:
# The product of two ciphertexts will decrypt to the sum of their corresponding plaintexts.
# So, we just need to factor the ciphertext into small enough numbers,
# decrypt those, and add them back together to get the plaintext.

largest_factor_length = 2048
# keep getting new encrypted flags until we get one that factors well
while largest_factor_length >= 2000:
    sock.recvuntil(b"paillier> ")
    sock.sendline(b"getflag")
    line = sock.recvline_startswith(b"Encrypted flag 2 (strong): ").decode()
    ciphertext = int(line.split(" ")[-1].strip())
    # this limit of 2**26 was chosen because finds all the factors it can in about one second on my laptop.
    # again, there's a good chance one of your factors will be too large, in which case,
    # another encrypted flag will simply be fetched and we'll try again
    factors = list(factor_trial_division(ciphertext, 2**26))
    largest_factor_length = factors[-1][0].bit_length()
    print(f"obtained {len(factors)} factors, largest is {factors[-1][0].bit_length()}")

# decrypt every factor and add them together to build the plaintext
plaintext = 0
for factor, multiplicity in factors:
    sock.recvuntil(b"paillier> ")
    sock.sendline(b"decrypt")
    sock.recvuntil(b"Number, c, to decrypt? ")
    sock.sendline(str(factor).encode())
    line = sock.recvline_startswith(b"Plaintext for c: ").decode()
    decrypted_factor = int(line.split(" ")[-1].strip())
    plaintext += decrypted_factor * multiplicity
    plaintext %= n
    print(f"decrypted factor {factor} with multiplicity {multiplicity}")

# Each byte of the plaintext is an ascii character;
# we can use `digits()` with base 256 to quickly decompose the solution,
# although we'll need to also reverse them.
chars = [chr(d) for d in list(Integer(plaintext).digits(256))]
chars.reverse()
answer = "".join(chars)

print(answer)
