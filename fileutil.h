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

typedef BOOL (CALLBACK * PKULL_M_FILE_FIND_CALLBACK) (DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);

BOOL kull_m_file_getCurrentDirectory(wchar_t ** ppDirName);
BOOL kull_m_file_getAbsolutePathOf(PCWCHAR thisData, wchar_t ** reponse);
BOOL kull_m_file_isFileExist(PCWCHAR fileName);
BOOL kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);	// for 'little' files !
void kull_m_file_cleanFilename(PWCHAR fileName);
PWCHAR kull_m_file_fullPath(PCWCHAR fileName);
BOOL kull_m_file_Find(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/, DWORD level, BOOL isPrintInfos, PKULL_M_FILE_FIND_CALLBACK callback, PVOID pvArg);