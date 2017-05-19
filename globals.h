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
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "fileutil.h"
#include "process.h"

#define WANA_PUBKEY_FILE	L"00000000.pky"
#define WANA_PRIKEY_FILE	L"00000000.dky"
#define WANA_FILE_EXT		L".WNCRY"


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define kprintf wprintf

#ifndef PRINT_ERROR
#define PRINT_ERROR(...) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " __VA_ARGS__))
#endif

#ifndef PRINT_ERROR_AUTO
#define PRINT_ERROR_AUTO(func) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

#ifndef W00T
#define W00T(...) (kprintf(TEXT(__FUNCTION__) L" w00t! ; " __VA_ARGS__))
#endif