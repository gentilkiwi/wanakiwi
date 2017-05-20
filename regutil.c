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
#include "regutil.h"

BOOL kull_m_reg_delete_PendingFileRenameOperations() {
	DWORD dwRet;
	HKEY hSessionManager;
	UCHAR buffer[1024];
	BOOL Status = FALSE;

	dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\",
			FALSE, KEY_ALL_ACCESS, &hSessionManager);
	if (dwRet != ERROR_SUCCESS) return FALSE;

	DWORD bufferSize = sizeof(buffer);
	dwRet = RegQueryValueEx(hSessionManager, TEXT("PendingFileRenameOperations"), NULL, NULL, buffer, &bufferSize);
	if ((dwRet == ERROR_MORE_DATA) || (dwRet == ERROR_SUCCESS)) {
		kprintf(L"\"PendingFileRenameOperations\" registry value is present and will now be deleted.\n");

        //
        // RegDeleteKeyValue() is only Vista+
        //
        dwRet = RegDeleteValue(hSessionManager, TEXT("PendingFileRenameOperations"));
		if (dwRet == ERROR_SUCCESS) {
			kprintf(L"\"PendingFileRenameOperations\" successfuly removed.\n");
			Status = TRUE;
		} else {
			kprintf(L"\"PendingFileRenameOperations\" was not removed.\n");
		}
	}

	RegCloseKey(hSessionManager);

	return Status;
}