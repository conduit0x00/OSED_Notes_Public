https://learn.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-170
https://cs155.stanford.edu/papers/formatstring-1.2.pdf
## Some Specifiers

| Specifier | Reads from memory  |
|---|---|
|%c |a single character|
|%s|**a string.  The corresponding argument must be a pointer.**|
|%d|a decimal integer (assumes base 10)|
|%i|a decimal integer (detects the base automatically)|
|%o|an octal (base 8) integer|
|%x|**a hexadecimal (base 16) integer**|
|%p|**an address (or pointer)**|
|%f|a floating point number for floats|
|%u|**int unsigned decimal**|
|%e|a floating point number in scientific notation|
|%E|a floating point number in scientific notation|
| %n | **Nothing printed. The corresponding argument must be a pointer to a signed int. The number of characters written so far is stored in the pointed location.**|
## Which specifiers for what
### %s
Read from pointer at the offset on the stack of the %s in to the string (arb-read if you control stack).

Can spam this to easily check for format string vulns as it will probs crash the process.
### %p, %x, %u
Leaks.
```c
"%p:%p:%p:..." -> pointers
"%08x:%08x:%08x:..." -> raw memory
```
### %n
Write arbitrary character at stack offset from arg
## Modifiers
#### Padding
```c
"%10p%n"
```
This will essentially act as 10 pointers offset from the stack, then the %n
https://cplusplus.com/reference/cstdio/printf/
#### Length specifiers
|   |  specifiers |   |   |   |   |   |   |
|---|---|---|---|---|---|---|---|
|*length*|	**d i**|	**u o xX**	|**f F e E g G a A**|	**c**| **s**	|**p**	|**n**|
|**(none)**|	int	|unsigned int	|double|	int	|char*	|void*|	int*|
|hh|	signed char|	unsigned char	|	|		|	| |signed char*
|**h**	|short int	|unsigned short int				| | | | |	short int*
|**l**	|long int|	unsigned long int		|wint_t	|wchar_t*	|	long int*
|**ll**	|long long int	|unsigned long long int			| | | | |		long long int*
|**j**	|intmax_t|	uintmax_t				| | | | |	intmax_t*
|**z**	|size_t	|size_t				| | | | |	size_t*
|**t**|	ptrdiff_t	|ptrdiff_t			| | | | |		ptrdiff_t*
|**L**		| | |	long double		| | | | |		
# Example of a format string bug in assembly

![[snprintf_format_bug.png]]
Here we see a call to `snprintf`. This and similarly vulnerable functions take a format string and a contents buffer. However, given that we're in x86, this all happens on the stack. Notice that we've only moved `edx` on to the stack as the format string, and nothing above it.

If you do not provide both buffer and format args, then any format strings in the buffer will act on the following memory on the stack. There will be pointers in there. This is also achievable where you have user controlled format strings at all, as you can write arbitrary numbers of format specifiers, exhausting any existing following args.