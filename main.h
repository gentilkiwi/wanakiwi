/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	With BIG thanks and love to:
	- @msuiche <3
	- @halsten
	- @malwareunicorn
	- @adriengnt	(https://github.com/aguinet/wannakey)
		This guy discovered how to retrieve prime numbers of the private key when it's not possible to get it in a normal way
		He rocks \o/ - I was unable to fix his code where the Private Key is malformed, so I made it here with OpenSSL lib :)

	.. Just to help ...

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "rsautil.h"

typedef struct _DECRYPT_DATA {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	DWORD count;
} DECRYPT_DATA, *PDECRYPT_DATA;

DWORD findProcess();
BOOL CALLBACK file_callback_wncry(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);
BOOL CALLBACK file_callback_publickey(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);