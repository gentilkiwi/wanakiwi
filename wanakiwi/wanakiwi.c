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
#include "wanakiwi.h"

int wmain(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_SUCCESS;
	KULL_M_MEMORY_TYPE Type;
	PBYTE data;
	DWORD cbData;
	PCWCHAR szData, szPubSearch, szSearch, szPrivSave;
	HANDLE hProcess = NULL;
	DWORD pid = 0;
	PWCHAR p, fPub = NULL;

	DECRYPT_DATA dData = {0};
	RSA_MEMORY kData = {0};

	if(CryptAcquireContext(&dData.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) // we'll do RSA / AES stuff
	{
		kull_m_string_args_byName(argc, argv, L"pubsearch", &szPubSearch, L"c:");
		kull_m_string_args_byName(argc, argv, L"search", &szSearch, L"c:");
		
		if(kull_m_string_args_byName(argc, argv, L"priv", &szData, NULL))
		{
			kprintf(L"Private key file on command-line: %s, will use it instead searching\n", szData);
			if(kull_m_file_readData(szData, &data, &cbData))
			{
				if(!CryptImportKey(dData.hProv, data, cbData, 0, 0, &dData.hKey))
					PRINT_ERROR_AUTO(L"CryptImportKey");
				LocalFree(data);
			}
		}
		else if(kull_m_file_readData(WANA_PRIKEY_FILE, &data, &cbData))
		{
			kprintf(L"Private key (" WANA_PRIKEY_FILE L") is in current directory, let\'s use it\n");
			if(!CryptImportKey(dData.hProv, data, cbData, 0, 0, &dData.hKey))
				PRINT_ERROR_AUTO(L"CryptImportKey");
			LocalFree(data);
		}
		else // without private key we'll need public key modulus to check primes with Adrien's method
		{
			if(kull_m_string_args_byName(argc, argv, L"pub", &szData, NULL))
			{
				kprintf(L"Public key file on command-line: %s, will use it instead searching\n", szData);
				fPub = _wcsdup(szData);
			}
			else if(kull_m_file_isFileExist(WANA_PUBKEY_FILE))
			{
				kprintf(L"Public key (" WANA_PUBKEY_FILE L") is in current directory, let\'s use it\n");
				fPub = _wcsdup(WANA_PUBKEY_FILE);
			}
			else
			{
				kprintf(L"Public key (" WANA_PUBKEY_FILE L") is NOT in current directory, let\'s search it (in %s)...\n", szPubSearch);
				if(!kull_m_file_Find(szPubSearch, NULL, TRUE, 0, FALSE, file_callback_publickey, &fPub))
					PRINT_ERROR(L"Public key not found!\n");
			}

			if(fPub)
			{
				if(rsautil_pubkeyfile_to_new_e_n(fPub, &kData.bn_e, &kData.bn_modulus))
				{
					printBN(L"Modulus : ", kData.bn_modulus, L"\n");
					printBN(L"Exponent: ", kData.bn_e, L"\n");

					if(kull_m_string_args_byName(argc, argv, L"mdmp", &szData, NULL) || kull_m_string_args_byName(argc, argv, L"dmp", &szData, NULL))
					{
						Type = KULL_M_MEMORY_TYPE_PROCESS_DMP;
						kprintf(L"Dealing with a minidump file: %s\n", szData);
						hProcess = CreateFile(szData, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					}
					else
					{
						Type = KULL_M_MEMORY_TYPE_PROCESS;
						if(kull_m_string_args_byName(argc, argv, L"process", &szData, NULL))
						{
							kprintf(L"Process name on command-line: %s, first process with this name will be inspected\n", szData);
							if(kull_m_process_getProcessIdForName(szData, &pid))
								kprintf(L"Process found with PID %u\n", pid);
							else PRINT_ERROR(L"No process with \'%s\' name was found...\n", szData);
						}
						else if(kull_m_string_args_byName(argc, argv, L"pid", &szData, NULL))
						{
							kprintf(L"Process id on command-line: %s, process with this PID will be inspected\n", szData);
							pid = wcstoul(szData, NULL, 0);
						}
						else
						{
							kprintf(L"No process specified, searching for common process...\n");
							if(!(pid = findProcess()))
								PRINT_ERROR(L"No process found\n");
						}

						if(pid)
							hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
						else PRINT_ERROR(L"No valid PID\n");
					}

					if(hProcess && (hProcess != INVALID_HANDLE_VALUE))
					{
						if(kull_m_memory_open(Type, hProcess, &kData.hProcessMemory))
						{
							if(isValidArch(kData.hProcessMemory))
							{
								if(NT_SUCCESS(kull_m_process_getMemoryInformations(kData.hProcessMemory, MemoryAnalysis, &kData)))
								{
									if(kData.rsa)
									{
										if(rsautil_rsa_to_privkeyblob(kData.rsa, &data, &cbData))
										{
											if(!kull_m_string_args_byName(argc, argv, L"noprivsave", NULL, NULL))
											{
												if(!kull_m_string_args_byName(argc, argv, L"privsave", &szPrivSave, NULL))
												{
													if(p = wcsrchr(fPub, L'.'))
													{
														*(p + 1) = L'd';
														szPrivSave = fPub;
													}
													else szPrivSave = WANA_PRIKEY_FILE;
												}
												kprintf(L"Let\'s save privatekey blob in %s file (for wanadecrypt or original Wana Decrypt0r 2.0...)\n", szPrivSave);
												kull_m_file_writeData(szPrivSave, data, cbData);
											}
											else kprintf(L"Only dealing without saving key on disk when /noprivsave argument is used\n");

											if(!CryptImportKey(dData.hProv, data, cbData, 0, 0, &dData.hKey))
												PRINT_ERROR_AUTO(L"CryptImportKey");
											LocalFree(data);
										}
										else PRINT_ERROR(L"OpenSSL don\'t want to convert it to MS PRIVATEKEYBLOB format\n");
										RSA_free(kData.rsa);
									}
									else PRINT_ERROR(L"Unfortunately, no correct privatekey in memory :(\n");
								}
								else PRINT_ERROR(L"Minidump without MemoryInfoListStream?\n");
							}
							else PRINT_ERROR(L"Memory is not PROCESSOR_ARCHITECTURE_INTEL\n");
						}
						CloseHandle(hProcess);
					}
					else PRINT_ERROR_AUTO(L"Invalid handle (CreateFile/OpenProcess)");
					BN_free(kData.bn_e);
					BN_free(kData.bn_modulus);
				}
				free(fPub);
			}
		}

		if(dData.hKey)
		{
			if(!kull_m_string_args_byName(argc, argv, L"nodecrypt", NULL, NULL))
			{
				if((Type == KULL_M_MEMORY_TYPE_PROCESS) || kull_m_string_args_byName(argc, argv, L"forcedecrypt", NULL, NULL))
				{
					rsautil_initdefaultkey(&dData.hFreeProv, &dData.hFreeKey);
					kprintf(L"Now searching " WANA_FILE_EXT L" files in %s...\n", szSearch);
					kull_m_file_Find(szSearch, NULL, TRUE, 0, FALSE, file_callback_wncry, &dData);
					rsautil_freedefaultkey(dData.hFreeProv, dData.hFreeKey);
				}
				else kprintf(L"Only dealing with keys in MINIDUMP mode, use /forcedecrypt to search for files\n");
			}
			else kprintf(L"Only dealing with keys when /nodecrypt argument is used\n");
			CryptDestroyKey(dData.hKey);
		}
		CryptReleaseContext(dData.hProv, 0);
	}
	else PRINT_ERROR_AUTO(L"CryptAcquireContext");

	kull_m_reg_delete_PendingFileRenameOperations();
	return status;
}

const PCWCHAR proc[] = {
	L"wnry.exe",
	L"wcry.exe",
	L"data_1.exe",
	L"tasksche.exe",
	L"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe",
	L"5ff465afaabcbf0150d1a3ab2c2e74f3a4426467.exe",
	L"84c82835a5d21bbcf75a61706d8ab549.exe",
};
DWORD findProcess()
{
	DWORD i, p = 0;
	for (i = 0, p = 0; i < ARRAYSIZE(proc); i++)
	{
		if(kull_m_process_getProcessIdForName(proc[i], &p))
		{
			kprintf(L"Process \'%s\' found with PID: %u\n", proc[i], p);
			break;
		}
	}
	return p;
}

BOOL CALLBACK MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	BOOL found = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {pMemoryBasicInformation->BaseAddress, ((PRSA_MEMORY) pvArg)->hProcessMemory};
	PBYTE i, end;
	DOUBLE entropy;
	BIGNUM *bn_prime1, *bn_prime2;
	BN_CTX *ctx;

	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_RESERVE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		kprintf(L".");
		if(aBuffer.address = LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize))
		{
			if(kull_m_memory_copy(&aBuffer, &aProcess, pMemoryBasicInformation->RegionSize))
			{
				ctx = BN_CTX_new();
				BN_CTX_start(ctx);
				bn_prime1 = BN_CTX_get(ctx);
				bn_prime2 = BN_CTX_get(ctx);
				kull_m_memory_reverseBytes(aBuffer.address, pMemoryBasicInformation->RegionSize);
				end = (PBYTE) aBuffer.address + pMemoryBasicInformation->RegionSize - RSA_2048_PRIM;
				for(i = (PBYTE) aBuffer.address; (i < end) && !found; i += 4)
				{
					entropy = rsautil_normalizedEntropy(i, RSA_2048_PRIM);
					if(entropy > 0.8)
					{
						BN_bin2bn(i, RSA_2048_PRIM, bn_prime1);
						if(rsautil_is_prime_div_and_diff(((PRSA_MEMORY) pvArg)->bn_modulus, bn_prime1, bn_prime2))
						{
							printBN(L"\nPrime1: ", bn_prime1, L"\n");
							printBN(L"Prime2: ", bn_prime2, L"\n");
							((PRSA_MEMORY) pvArg)->rsa = RSA_new();
							if(!(found = rsautil_quickimport(((PRSA_MEMORY) pvArg)->rsa, ((PRSA_MEMORY) pvArg)->bn_e, bn_prime1, bn_prime2, NULL)))
							{
								PRINT_ERROR(L"Unable to import raw key as a RSA key (?) -- continue\n");
								RSA_free(((PRSA_MEMORY) pvArg)->rsa);
								((PRSA_MEMORY) pvArg)->rsa = NULL;
							}
						}
					}
				}
				BN_CTX_end(ctx);
				BN_CTX_free(ctx);
			}
			else PRINT_ERROR(L"memory copy @ p (%u)\n", pMemoryBasicInformation->BaseAddress, pMemoryBasicInformation->RegionSize);
			LocalFree(aBuffer.address);
		}
	}
	return !found;
}

BOOL CALLBACK file_callback_publickey(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	BOOL status = FALSE;
	if(status = (_wcsicmp(path, WANA_PUBKEY_FILE) == 0))
	{
		kprintf(L"Public key found: %s\n", fullpath);
		*(PWSTR *) pvArg = _wcsdup(fullpath);
	}
	return status;
}

BOOL CALLBACK file_callback_wncry(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	BOOL status = FALSE;
	PDECRYPT_DATA pData = (PDECRYPT_DATA) pvArg;
	PWSTR ext = PathFindExtension(path);
	if(ext && (_wcsicmp(ext, WANA_FILE_EXT) == 0))
		rsautil_decryptFileWithKey(pData->hProv, pData->hKey, pData->hFreeKey, (LPWSTR) fullpath);
	return status;
}

void printBN(PCWCHAR pre, BIGNUM *bn, PCWCHAR post)
{
	PCHAR outs;
	if(pre)
		kprintf(pre);
	outs = BN_bn2hex(bn);
	kprintf(L"%S", outs);
	OPENSSL_free(outs);
	if(post)
		kprintf(post);
}

BOOL isValidArch(PKULL_M_MEMORY_HANDLE hMemory)
{
	BOOL status = FALSE;
	PMINIDUMP_SYSTEM_INFO pInfos;
	if(hMemory->type == KULL_M_MEMORY_TYPE_PROCESS_DMP)
	{
		if(pInfos = (PMINIDUMP_SYSTEM_INFO) kull_m_minidump_stream(hMemory->pHandleProcessDmp->hMinidump, SystemInfoStream))
			status = (pInfos->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL);
		else PRINT_ERROR(L"Minidump without SystemInfoStream (?)\n");
	}
	else status = FALSE;
	return TRUE;
}

BOOL kull_m_reg_delete_PendingFileRenameOperations()
{
	BOOL status = FALSE;
	HKEY hKey;
	DWORD dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", FALSE, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
	if(dwRet == ERROR_SUCCESS)
	{
		dwRet = RegQueryValueEx(hKey, L"PendingFileRenameOperations", NULL, NULL, NULL, NULL);
		if(dwRet == ERROR_SUCCESS)
		{
			kprintf(L"\'PendingFileRenameOperations\' registry value is present and will now be deleted\n");
			dwRet = RegDeleteValue(hKey, L"PendingFileRenameOperations");
			if(!(status = (dwRet == ERROR_SUCCESS)))
				PRINT_ERROR(L"RegDeleteValue: %u\n", dwRet);
		}
		else if(dwRet != ERROR_FILE_NOT_FOUND) PRINT_ERROR(L"RegQueryValueEx: %u\n", dwRet);
		RegCloseKey(hKey);
	}
	else PRINT_ERROR(L"RegOpenKeyEx: %u\n", dwRet);
	return status;
}