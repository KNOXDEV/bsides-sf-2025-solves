# ruthless-dot-flag-2
Original Prompt:
```
There is a whole extra layer to ruthless-dot-flag challenge! Can you find the second hidden flag?
```

Looking at the result of the first part, we see an obvious source of noise at the top of the
image. From experience with steg, we know this is likely another embedded file. 

After converting the image to `png24` format, we can look at the image in
[StegOnline](https://georgeom.net/StegOnline/upload)
and experiment with browsing bitplanes to quickly and visually see
which bitplanes contain extra information. After concluding that only the most sigificant bit
contains the desired information, we extract it to a file and notice that the resulting
file has a valid PNG header. We change the extension to `.png`, and we can view the flag.