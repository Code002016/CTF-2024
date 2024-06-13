from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('chall')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
lib= ELF('libc-2.31.so')
ld  =ELF('ld-2.31.so')

def malloc(idx, size):
    r.sendlineafter(b">> ", b"1")
    r.sendlineafter(b"Index\n>> ", idx)
    r.sendlineafter(b"Size\n>> ", size)
def chage_size(idx, data):
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b"Index\n>> ", idx)
    r.sendlineafter(b"Size\n>> ", size)

def free(idx):
    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b"Index\n>> ", idx)
    # r.sendlineafter(b"Data\n>> ", data)

def edit(idx, data):
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b"Index\n>> ", idx)
    r.sendlineafter(b"Data\n>> ", data)
    

# for i in range(7):
    # malloc(i,0x40)
# for i in range(7):
    # free(i)
    
# malloc(0,0x40)
# edit(0,0x40)
# free(0)

# malloc(1,0x400);
# free(0)

r.interactive()
