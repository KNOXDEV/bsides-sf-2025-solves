# dragon-name
Original Prompt:
```
Can you find the flag on the app? 
```

Basically, using JDAX, find the usercode from the provided apk.

```bash
jadx-gui ./src/distfiles/dragon-name.apk
```

I then extracted this code from `com.example.dragonnames.MainActivity`:

```java
    public final String createFlag() throws Resources.NotFoundException {
        String part1 = rot13("PGS");
        byte[] b64 = Base64.decode$default(Base64.INSTANCE, "dzNhaw==", 0, 0, 6, (Object) null);
        String part2 = StringsKt.decodeToString(b64);
        String part3 = "T0";
        String part4 = getResources().getString(R.string.part4);
        Intrinsics.checkNotNullExpressionValue(part4, "getString(...)");
        String part5 = "Typ3";
        String flag = part1 + "{" + part2 + part3 + part4 + part5 + "}";
        return flag;
    }
```

Then I used the following prompt to opencode (KLM K2.5):

```
@solutions/mobile/easy - dragon-name/README.md Look at the snippet of decompiled Java code in this file and create a Python script @solutions/mobile/easy - dragon-name/solve.py that does the same thing
```

This resulted in [`solve.py`](./solve.py), although it is worth noting that the model noticed the resource string (part 4) was missing and grabbed it directly from the challenge source. In a real CTF, I would need to go find this, although doing so would not be difficult
(It's under `Resources/resources.arsc/res/values/string.xml` in JADX).