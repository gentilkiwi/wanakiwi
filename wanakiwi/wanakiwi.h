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
	This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#pragma once
#include "globals.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_file.h"
#include "rsautil.h"

typedef struct _RSA_MEMORY_DATA {
	PKULL_M_MEMORY_HANDLE hProcessMemory;
	DOUBLE minEntropy;
	BIGNUM *bn_modulus;
	BIGNUM *bn_e;
	RSA *rsa;
} RSA_MEMORY, *PRSA_MEMORY;

typedef struct _DECRYPT_DATA {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTPROV hFreeProv;
	HCRYPTKEY hFreeKey;
} DECRYPT_DATA, *PDECRYPT_DATA;

int wmain(int argc, wchar_t * argv[]);
DWORD findProcess();
BOOL CALLBACK MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
BOOL CALLBACK file_callback_publickey(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);
BOOL CALLBACK file_callback_wncry(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);
void printBN(PCWCHAR pre, BIGNUM *bn, PCWCHAR post);
BOOL isValidArch(PKULL_M_MEMORY_HANDLE hMemory);
BOOL kull_m_reg_delete_PendingFileRenameOperations();