## Quick Check List for Remotes
1. What open sockets does the program own?
2. Is there a menu (command line or GUI)? If there is, what things allow input or can cause state changes?
3. Is there a help command? Use it.
4. Are there debug strings? They're useful for navigation.
	- When navigating, both string search and symbol search are quick wins, look for interesting words (and shortened versions) like:
		- Create (new)
		- Receive (recv)
		- Allocate (Alloc)
		- Execute (exec, run, start)
		- Debug (dbg)
		- Developer (dev)
5. Figure out what attack surface is actually reachable remotely and focus there.
6. Is there a state machine/message loop? Find it and follow the states to uncover functionality. This will lead to opcodes and make protocol RE easier.
	- If you find a set of opcodes but don't think its all of them, how do you use them? Try fuzzing that field with other values.
7. Check for format string bugs, they're the easiest wins.
8. Check for all instances of data being received by the client and trace source to sink
	- Don't forget that you can have IDA perform pathing algorithms between two function nodes, makes this a lot easier. Remember it may not get everything though.
9. Check for all the listed vulnerable functions

Indirect tasks:
1. Check CVE's for the product and others in the product line/by the company for common attack surface
2. Check which libraries are in use and whether they have active CVE's
3. Check code surrounding library integration depending on the types of library
## Easy Win Searches
### Functions

| Function      | Description |
| ----------- | ----------- |
| `gets`     | Avoid `gets` function as it can lead to reads beyond buffer boundary and cause buffer overflows. Some secure alternatives are `fgets` and `gets_s`.|
| `getwd`     | Avoid the `getwd` function, it does not check buffer lengths. Use `getcwd` instead, as it checks the buffer size.        |
| `scanf`     | Avoid `scanf` function as it can lead to reads beyond buffer boundary and cause buffer overflows. A secure alternative is `fgets`.       |
| `strcat`, `strncat`     | Avoid `strcat` or `strncat` functions. These can be used insecurely causing non null-termianted strings leading to memory corruption. A secure alternative is `strcat_s`.        |
| `strcpy`, `strncpy`    | Avoid `strcpy` or `strncpy` function. `strcpy` does not check buffer lengths. A possible mitigation could be `strncpy` which could prevent buffer overflows but does not null-terminate strings leading to memory corruption. A secure alternative (on BSD) is `strlcpy`.       |
| `strtok`     | Avoid `strtok` function as it modifies the original string in place and appends a null character after each token. This makes the original string unsafe. Suggested alternative is `strtok_r` with `saveptr`.        |
| `printf`, `sprintf`, `vsprintf`     | Avoid user controlled format strings like "argv" in `printf`, `sprintf` and `vsprintf` functions as they can cause memory corruption. Some secure alternatives are `snprintf` and `vsnprintf`.       |

### Assembly
#### String Instructions
![[string_instr_table_Ophir_harpaz.png]]
## Adjacent Functions
Interesting stuff near these, good to break on to get close to what you want

| Function      | Description |
| ----------- | ----------- |
| `memcpy`     | Interesting stuff happens around memcpy|
| `malloc`     | Interesting stuff happens around malloc, look for cases with no `memset`|
| `recv`     | Receiving data from a socket|
## Pitfalls
- Make sure that you don't write off fail cases as non-interesting, maybe they do something weird
## Scanner Query Definition Links
### CodeQL
https://codeql.github.com/codeql-query-help/cpp/
```
https://github.com/github/codeql/tree/main/cpp/ql/src/Likely%20Bugs

https://github.com/github/codeql/tree/main/cpp/ql/src/Security/CWE

https://github.com/github/codeql/tree/main/cpp/ql/src/Critical
```
### Joern
https://queries.joern.io/