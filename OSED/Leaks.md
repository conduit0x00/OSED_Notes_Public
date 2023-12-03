### API
- dbghelp APIs
### Pivot From Any module -> All Imported modules
- Get any module leak.
- Find any gadgets accessing `[fs:x]` which you can use to leak PEB
- Parse module list
### Format Strings
*Any time a function that can take format specifiers doesn't have them, you can insert them in the base input to leak memory. Reads values from the stack.*

| Specifier | Reads from memory  |
|---|---|
|%c|a single character|
|%s|a string|
|%hi|short (signed)|
|%hu|short (unsigned)|
|%Lf|long double|
|%d|a decimal integer (assumes base 10)|
|%i|a decimal integer (detects the base automatically)|
|%o|an octal (base 8) integer|
|%x|**a hexadecimal (base 16) integer**|
|%p|**an address (or pointer)**|
|%f|a floating point number for floats|
|%u|**int unsigned decimal**|
|%e|a floating point number in scientific notation|
|%E|a floating point number in scientific notation|

### Buffer Manipulation
*Requires some setup, if you have a format string or array leak, they'll be easier.*
#### One Byte Overflow

> [!note] Larger overflows
> If you have an arbitrary overflow and no other leak, you can still do all of these, just overflow a single byte
##### BSTRS
- If you are working with `BSTR` strings which are allocated back to back, you can overflow in to the length prefix of the subsequent string
- If you can then read that string you have a leak primitive
- Works similarly for any types in which one member controls the length of another
##### `Null` terminated strings (truncated)
- Often you'll find that you can get a one byte overflow in a `null` terminated string, however rather than actually overflowing, it just truncates off the null terminator
- Given that the string is no longer terminated, if you can read it, you'll get memory up until the next null byte, often enough for a pointer leak
##### `Null` terminated strings (not truncated)
- If you are able to write what should be a `null` terminated string, but appending the `null` is left up to the user, just don't append it. When you read it, it will leak.
- If you have a non-truncated `null` terminated string but it also always gets `null` appended, if its allocated next to another variable you can evoke a write to, then you are not out of luck
	1. First, overflow the string. This overwrites the first byte of the next object with a null.
	2. At this point you still can't leak anything due to the null. To get around this, cause a write to the second object.
	3. This overwrites the null. When you read from the string, you'll be able to read subsequent memory
#### Other Overflows
##### Types with a pointer to buffer
- If you can evoke allocation of a type which contains pointer to a buffer:
	- If there is a read buffer function, if you can overflow the pointer you have some form of read (full pointer -> arb-read)
	- Bonus: If there is a write buffer function, you have some form of read (full pointer -> arb-read)
### Array Accesses
*Very easy to perform leaks, just index in to the array properly.*

- Sometimes you find array accesses without proper bounds checking (either `<=` or just straight up missing)
- `<=` or similar gives you a one-element read past the array
- Improper bounds checking is arb-read for addresses > array
---
> [!note] 
> Stuff below here is probably not that OSED-y, it's a little more advanced considering its mostly heap things.
### Improperly Initialised Memory
*Respectively the hardest form of leaks, as you either need to groom or be lucky with available objects if you don't have full execution.*

- When calling `malloc` you should always immediately `memset` to initialise the memory and avoid leaving it un-sanitised
- If memory allocated by `malloc` is read from without first performing `memset` on that are, there may be dangling pointers.
- If an object that you are able to evoke a read from is allocated in this area as such (or it is initialised without performing `memset` on its members) then you can leak the un-sanitised memory
- If you are able to cause an object to exist at a pointer to un-sanitised memory without actually overwriting anything, this could be a pretty good leak
### UAF
*Similar to the above, except while allocator thinks object is dead, something else doesn't*

With the below, what I mean by constrained type confusion is that we likely cannot craft useful fake objects, as we're assuming we've not achieved a leak yet. Therefore any type confusion we are able to do must be constrained to only properly formed and allocated objects (rather than say allocating a string in to a hole and modifying it as we see fit to create a fake).
#### Constrained type confusion, member read
Requires that `memset` isn't called during the initialisation of the type you use for the confusion.
If types are bucketed in to their own regions, requires a possible groom to get stuff lining up correctly.

- Rather than trying to get execution from the UAF by overlapping a pointer/some code, just overlap such that you can read out a member containing a pointer
- To be able to do this, 'just' get the allocator to put an object with a readable member on top of the memory you want to read 
#### Constrained type confusion, pointer overlap
Even if you are not able to chain full arbitrary execution yet, you can chain a read from a type confused object as a leak.
If types are bucketed, you can do this with same type UAF, just need full control over a pointer (callback/lookup or something) within that type

- Do this by grooming an object in to the UAF slot such that a pointer to a function with a read is overlapping a pointer on the old object that you can cause to be called, in a way that you'll get the output
- Doesn't require you to know addresses, just get the correct object type allocated
- If you don't get anything useful back the first time, you can probably just keep doing this until you do
- Afterwards, you're lucky, you can just use the same UAF to get arbitrary execution now that you know deterministic values
