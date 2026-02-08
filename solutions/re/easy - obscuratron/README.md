# obscuratron
Original Prompt:
```
We've obtained an encrypted document and the secret software used to encrypt
it! But we can't find the decryption tool, can you figure out how to decrypt
it?
```

This is a simple primer with binary reversing. I used Ghidra and the decompiler found a function with the following psuedocode:

```c
  local_c = fgetc(stdin);
  local_c = local_c ^ 0xab;
  putchar(local_c);
  local_10 = fgetc(stdin);
  while (-1 < (int)local_10) {
    local_c = local_10 ^ local_c;
    putchar(local_c);
    local_10 = fgetc(stdin);
  }
```

This is a revolving xor cipher. The only catch is that its not 100% symmetric,
you'll need to make sure the key used for each iteration of the decryption algorithm
is the previous ENCRYPTED byte, not the previous decrypted one. See [`solve.ts`](./solve.ts).