from pwn import *
from ctypes import *
import time

context.log_level = 'debug'
context.arch = "amd64"

if len(sys.argv) > 1:
    first_arg = int(sys.argv[1])
    
e = context.binary = ELF('chal')
# r= e.process()
r= remote('34.70.212.151', 8006)
lib = e.libc

proc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
timefunc = proc.time
srand = proc.srand
rand = proc.rand
srand(timefunc(0)+first_arg)


li = ["Apple", "Orange", "Mango", "Banana", "Pineapple", "Watermelon", "Guava", "Kiwi", "Strawberry", "Peach"]
for i in range(50):
    r.sendlineafter(b"Your guess : ", li[rand() % 10].encode())
r.interactive()