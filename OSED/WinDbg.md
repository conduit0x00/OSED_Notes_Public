#WinDbg

### Step till next call or return
```windbg
pct
```

### Search
- a: ascii
- d: dword
- b: byte
- ...
```windbg
s -a 0x0 L?800000000 thing
``` 
### Exceptions
```windbg
sx  # List
sxe # Enable
sxd # Second chance
sxn # Notify
sxi # ignore
```
Handlers:
```windbg
!exchain
```
### dx
Start with and build from
```windbg
dx @$curprocess
```

### Limit symbols to speed them up
```
.sympath srv*c:\symbols
```

### Get to IAT
```windbg
lm                                      # Find name and base of module of interest
!dh $module_name -f                     # Dump module headers to get the IAT (base also 
										# in here)
dps $module_base + $IAT_offset L200     # Dump pointers from the IAT of the module with
										# symbols
```

### List out Regions and Protections
```
```windbg
!address -f:Image -c:".echo %1 %2 %3 %4 %5 %6 %7"
!address -f:Heap -c:".echo %1 %2 %3 %4 %5 %6 %7"
!address -f:Stack -c:".echo %1 %2 %3 %4 %5 %6 %7"
```