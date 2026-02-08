#!/usr/bin/env -S deno run --allow-read --allow-write

let fileBytes = await Deno.readFile("./src/distfiles/memo.pdf.enc");
let key = 0xab;

let decryptedFile = fileBytes.map((byte) => {
    let decrypted = byte ^ key;
    key = byte;
    return decrypted;
});

await Deno.writeFile("./memo.pdf", decryptedFile);