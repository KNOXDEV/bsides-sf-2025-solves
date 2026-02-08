# hoard
Original Prompt:
```
Can you raid the dragon's hoard??
```

This is less a PWN challenge and more a simple web app challenge.
I usually poke around those in my browser, then when I find a request I want to simulate and mess with,
right-click on the request in the Networking Tools window and "Copy as cURL".
Then you can paste that into [the cURL Converter website](https://curlconverter.com/javascript/)
to quickly get some code to start messing with (in `setup.ts`).

Because we're also given the flag path `/flag.txt` and `backend.php`, its fairly simple to see that this is a
shell injection vulnerability. By messing around with quotes and semicolons, we quickly get the flag.

It may also be possible to pop a reverse shell, but since its not necessary, that is an exercise left to the reader.