# pascals-homomorphism-2
Original Prompt:
```
Okay now you *really* have to break it. (Uses same service as part 1)
```

Basically, we have a decryption oracle, but we're only allowed to decrypt ciphertext smaller than 2000 bits.
Because n2 is 2048 bits, the odds of this happening naturally is astronomically small.

But, we can use the Paillier Cryptosystem's homomorphic property, which boils down to:
The product of two ciphertexts will decrypt to the sum of their corresponding plaintexts.

The trick is to keep pulling encrypted flags until you find one with small enough partial factors to all fit under this 2000 bit limit.
Then, you decrypt the factors individually and add them back up together to get the original plaintext.

Finding a routine in SageMath that does partial integer factorization was the hardest part for me,
there IS one under `sage.rings.factorint.factor_trial_division`.