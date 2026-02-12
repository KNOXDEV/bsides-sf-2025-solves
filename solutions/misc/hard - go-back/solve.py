#!/usr/bin/env python3

from pwnlib.tubes.remote import remote

sock = remote("localhost", 8080)

flag = ""

while '\n' not in flag:
    char = b"a"
    sock.recvuntil(b":~$ ")
    sock.sendline(b"./go-back " + flag.encode() + char)
    sock.recvuntil(b":~$ ")
    sock.sendline(b"echo $?")
    data = sock.recvuntil(b"ctf@")
    lines = data.decode().split("\r\n")
    # the error code we get is an unsigned byte,
    # which we need to reinterpret as signed
    diff = int.from_bytes(bytes([int(lines[1])]), signed=True)
    flag += chr(char[0] + diff)

print(flag)