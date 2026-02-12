# go-back
Original Prompt:
```
Can you figure out how to reveal the flag from this application?
```

An odd challenge that relies on undefined behavior from GCC.
Basically, if you don't return from a function that expects an integer,
what gets returned? Somehow, this is not illegal C and most standards mark it as
explicitly undefined behavior.

What gets returned is just whatever is left over in the `rax` register (on x86_64)
at the time the function `ret`s. And in the case of this function, 
we see thats the return value of `strcmp`.

The value of `strcmp` is not guaranteed by any standard to be anything other than positive, negative, or zero,
but in practice, its always the difference in value of the last characters to be compared from each string.

Meaning, the return value of this program is always the difference between the closest matching characters.
So, we can recover the original flag like so:

```bash
./go-back a
echo $? # 226 unsigned (-30 signed), so the correct character is (97-30 = 67) = "C"
./go-back Ca
echo $? # 243, repeat...
```