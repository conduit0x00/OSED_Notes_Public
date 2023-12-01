#seh #WinDbg 

## Overview
https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/seh-based-buffer-overflow

In TEB,
```asm
FS:[0x00]
```

SafeSEH applies to module containing gadget.

---
## Windbg

> [!tip] Show exception handler chain
> ``` windbg
>!exchain
>```

## Alternative #rop pivot gadget formats
https://iphelix.medium.com/getting-from-seh-to-nseh-5b9bdb481c72

## SEH To ROP

```asm
mov reg,[ebp+0c] + call [reg] (from corelan wallpaper) 

mov reg, fs:[0] / ... / ret (also from corelan wallpaper) 

pop regX / pop regY / pop regZ / call [regZ+8] 

push regX / mov regY,[esp+0xc] / call [regY+0xc] 

mov regY, [ebp+0xc] / push [regY-0x4] / ret 

mov regY, fs:[0] / mov reg, [regY-0x8] / jmp reg
```