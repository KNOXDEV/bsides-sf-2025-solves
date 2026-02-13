# acaan
Original Prompt:
```
This service listens on port 4113. When you connect, you send three things:

1. A filename to edit
2. An offset to edit
3. New content

That's it! The binary itself cannot be edited on disk, and that's pretty much
the only file we've added. The challenge is to figure out what to do with a
write-anywhere primitive.

Good luck!
```

A pretty detailed prompt that makes no effort to hide the nature of the vulnerability,
but how to connect the arbitrary file write primitive to arbitrary code execution is unclear.

I'll be completely honest; I have no `pwn` chops whatsoever. The most efficient way to train
in this category for me would be to take a general guess at an approach and attempt to 
generate the solution via AI. In the event that doesn't work, I have the AI write the exact solution
and explain it to me, then I attempt to implement my own from their explaination. 
I then write my own explanation here in this readme to make sure I understand all the princibles.

That is exactly what I did for this challenge. I asked the following question to a variety of models:

```
How would I use an arbitrary file write primitive to read the flag in this challenge?
You can look in @src/distfiles/ but not in @src/challenge/ or @src/solution/
```

Most models I tried (KLM K2.5, OpenCode's "Big Pickle", MiniMax 2.5, and finally Claude Opus 4.5) all
correctly (eventually) identified the key insight: you can turn an arbitrary file write to an arbitrary program memory write
by using the Linux filepath [`/proc/self/mem`](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html).
I correctly assumed something like this existed in the proc psuedo filesystem
but did not immediately remember the specifics. 

So, we can write no more than 2048 bytes to program memory. We'll need to write shellcode that prints the flag
and then somehow get the program to jump to that shell code. How we do that will depend on the security features
of this binary:

```Makefile
acaan: acaan.c
	gcc -Wall -m64 -fstack-protector-strong -no-pie -o acaan acaan.c
```

As you can see, stack smashing protection is enabled. If this were a buffer overflow challenge, this would matter
more than it does here, since we can write to any memory location, not just the stack, this probably will not affect us.

We can also see `-no-pie`, which means "No Position Independent Code". This means that the resulting binary
cannot be relocated by the Linux loader (which they typically would be for ASLR),
which means all important section addresses are at predictable locations.

With this information, our path is straightforward: we can seize control of execution by 
simply writing our shellcode to the `.text` section directly, right after the RIP after
calling `close()`. Note that this is possible due to the fact that `/proc/self/mem`
bypasses memory protections, apparently.

I used Claude Opus 4.5 to generate most of the shellcode and surrounding `pwntools` script,
and modified it until I understood it.