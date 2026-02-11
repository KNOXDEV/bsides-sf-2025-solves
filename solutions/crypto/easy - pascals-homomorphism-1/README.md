# pascals-homomorphism-1

Original Prompt:
```
We've implemented the Paillier cryptosystem for your hacking pleasure. Can you break it?
```

This is a cli service that you connect to via
```
docker compose up
nc localhost 8080
```

Once in, while you don't get source code, you can access exhaustive information about exactly what the problem is asking you to do.
There is an easy flag and a hard flag. I will focus on the first one. This is less so an explanation and more a documentation of
my personal struggles to get a satisfactory development environment.

The help text basically tells you that the easy flag is gettable by simply factoring `n` into its prime factors because the 
size is relatively small (192-bits). This is a bit misleading, as you cannot simply type `factor #` into a Linux terminal and
get an answer within a reasonable amount of time. Even when using GP/PARI (as the solution document suggests), you need at the 
very least a Quadratic Sieve to factor a prime of that size.

```bash 
gp
? factorint(n)
```

This gives the answer within a few seconds, but with debug printing on (`\g 3`), you can see that every conventional method tried (Pollard-Rho, Elipical Curve Method, etc) all fail before resulting to the more sophisicated Multiple Polynomial Quadratic Seive.
I bring this up because I'm looking for a way to reliably factor integers using an interface I will actually use (Python library, Node package) rather than just knowing that PARI/GP is a thing that exists and to use it (realistically, I never will).
On that note, I did try Python's `sympy` library's `factorint` function, but that library is written in pure Python and does not appear to support sieves, and is unlikely (in theory or my practice) to give an answer before the heat death of the universe.

`gmpy2` is a library that essentially just provides bindings into PARI, but it unfortunately is geared more towards
providing primitives, and as such does not contain an integer factoring routine. Perhaps a reasonably fast one could be written
with those primitives, but I did not have luck with those. 

There were some small indepenent (not-packaged) libraries that specifically implement the MPQS, but since these are non-native binaries, I have some doubts that they will perform reasonably, and they are slightly more difficult than I would prefer to install
(as they are not on PyPi or available in `nixpkgs`). In the future, I may need these libraries anyways (especially [`RsaCtfTool`](https://github.com/RsaCtfTool/RsaCtfTool?tab=readme-ov-file)), but I'll deal with that when I need it.

The elephant in the room that I have been ignoring is SageMath. While it is no doubt useful for many things in the crypto CTF space,
I've been intentionally avoiding it for as long as I can: it is big, bloated, and is not a normal Python library;
you generally have to interface with its DSL and combining its capabilities with other libraries you need for CTFs is not easy.
But it seems that I can't avoid it any longer, so to make things easier for me in the future, I'll bite the bullet.

After about a day of messing around with my IDE and Nix shell environment, I arrived at a setup that will let me write 
Python scripts that take advantage of most of Sage's math utilities while still having access to other useful things like pwnlib.
See [`solve.py`](./solve.py) for an example.