# cipher-block-corruption
Original Prompt:
```
We encrypted this flag for you. It doesn't seem to decrypt correctly?
```

The classic formula:

* you get the ciphertext
* you get the cipher program
* create a decryption program and get the plaintext, which contains the flag.

In this case, the ciphertext is a PNG file, and the algorithm used is AES-CBC.
This algorithm has the property that it is reversible as long as you have the key and the IV.
Unfortunately, we only have the key, so while most of it can be decrypted, the first block (16 bytes) are lost.

Thankfully, the first 16 bytes of any PNG file are the same: its the standard PNG header.

```python
"\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR"
```

So, decrypt the file with any IV, and then replace the first 16 bytes to recover the flag.