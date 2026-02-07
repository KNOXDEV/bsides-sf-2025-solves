#!/usr/bin/env python3

from Crypto.Cipher import AES # pycryptodome

with open("./src/distfiles/flag.png.enc", "rb") as flag:
    flag_bytes = flag.read()

K = bytes.fromhex("5f4dcc3b5aa765d61d8327deb882cf99")
aes = AES.new(K, AES.MODE_CBC)

# The flag is "corrupted" because the IV was not known and therefore randomized.
# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
# But, this will only affect the first 128 bits (16 bytes),
# which for PNG files, is fairly consistent
X = aes.decrypt(flag_bytes)

with open("flag.png", "wb") as enc:
    # this pretty much works, we just have to replace the first block
    # This was grabbed from a random PNG file
    enc.write(b'\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR')
    enc.write(X[16:])

