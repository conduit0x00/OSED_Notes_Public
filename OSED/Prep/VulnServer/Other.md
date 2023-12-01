> [!note]
>	The three paths I've completed are the most interesting, others are explained below.

## GSTET
Is essentially the same as KSTET, but you can't use GDOG, so just fire up another session instead

## GTER
Takes the input and converts it in to hex. Otherwise it is just a standard BOF

## LTER
A standard BOF with characters wrapping modulo 0x7f

## Other
All others are not vulnerable. GDOG can be used to store a value in a global variable.