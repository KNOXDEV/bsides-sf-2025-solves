# ruthless-dot-flag
Original Prompt:
```
Does the old game `ruthless.com` by the spy novelist hide something sinister?
```

We're provided a `flags.r16` binary file. Looking at it in a hex editor,
I see byte patterns that lead me to believe its image data of some kind.
Googling "r16 image" pulls up
[some results](https://developer.apple.com/documentation/coreimage/ciformat/r16)
that seem to imply the existence of a texture format made from a single channel of 16 bit numbers.

We use `wand` and `numpy` to parse the data assuming thats the case, and sure enough, 
after leaving room for an 18-byte header and by messing around with the image width,
we eventually convert the format to png, which visibly shows the flag.