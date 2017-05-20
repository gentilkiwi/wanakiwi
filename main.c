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
#include "main.h"

int wmain(int argc, wchar_t * argv[])
{
	DWORD pid = 0, previousPriv;
	PWSTR fPub = NULL;

	RSA *privRsa;
	BIGNUM *bn_modulus, *bn_e, *bn_prime1, *bn_prime2;
	BN_CTX *ctx;
	PBYTE pkBlob;
	DWORD cbPkBlob;

	BOOL found = FALSE;
	HANDLE hProcess;
	PBYTE currentPage, maxPage = MmSystemRangeStart;
	MEMORY_BASIC_INFORMATION memoryInfos;
	PBYTE buffer, i, end;
	DWORD cbBuffer;
	DOUBLE d;
	DECRYPT_DATA dData = {0};

	PCHAR outs;

	if(argc > 1)
	{
		pid = wcstoul(argv[1], NULL, 0);
		kprintf(L"Explicit PID: %u\n", pid);
	}

	RtlAdjustPrivilege(20, TRUE, FALSE, &previousPriv);
	if(pid || (pid = findProcess()))
	{
		if(kull_m_file_isFileExist(WANA_PUBKEY_FILE))
		{
			kprintf(L"Public key (" WANA_PUBKEY_FILE L") is in current directory, let\'s use it\n");
			fPub = _wcsdup(WANA_PUBKEY_FILE);
		}
		else
		{
			kprintf(L"Public key (" WANA_PUBKEY_FILE L") is NOT in current directory, let\'s search it...\n");
			if(!kull_m_file_Find(L"c:", NULL, TRUE, 0, FALSE, file_callback_publickey, &fPub))
				PRINT_ERROR(L"Public key not found!\n");
		}

		if(fPub)
		{
			ctx = BN_CTX_new();
			BN_CTX_start(ctx);

			bn_prime1 = BN_CTX_get(ctx);
			bn_prime2 = BN_CTX_get(ctx);
			if(rsautil_pubkeyfile_to_new_e_n(fPub, &bn_e, &bn_modulus))
			{
				outs = BN_bn2hex(bn_modulus);
				kprintf(L"Modulus  %S\n", outs);
				OPENSSL_free(outs);

				outs = BN_bn2hex(bn_e);
				kprintf(L"Exponent %S\n", BN_bn2hex(bn_e));
				OPENSSL_free(outs);

				if(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid))
				{
					kprintf(L"Searching for primes numbers in memory...\n");
					for(currentPage = 0; (currentPage < maxPage) && !found; currentPage += memoryInfos.RegionSize)
					{
						if(VirtualQueryEx(hProcess, currentPage, &memoryInfos, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
						{
							if((memoryInfos.Type == MEM_PRIVATE) && (memoryInfos.State != MEM_RESERVE) && (memoryInfos.Protect == PAGE_READWRITE))
							{
								kprintf(L".");
								if(buffer = (PBYTE) LocalAlloc(LPTR, memoryInfos.RegionSize))
								{
									if(ReadProcessMemory(hProcess, currentPage, buffer, memoryInfos.RegionSize, &cbBuffer))
									{
										kull_m_memory_reverseBytes(buffer, memoryInfos.RegionSize);
										end = buffer + memoryInfos.RegionSize - RSA_2048_PRIM;
										for(i = buffer; (i < end) && !found; i += 4)
										{
											d = rsautil_normalizedEntropy(i, RSA_2048_PRIM);
											if(d > 0.8)
											{
												BN_bin2bn(i, RSA_2048_PRIM, bn_prime1);
												if(found = rsautil_is_prime_div_and_diff(bn_modulus, bn_prime1, bn_prime2))
												{
													outs = BN_bn2hex(bn_prime1);
													kprintf(L"\nPrime1 %S\n", outs);
													OPENSSL_free(outs);
													outs = BN_bn2hex(bn_prime2);
													kprintf(L"Prime2 %S\n", BN_bn2hex(bn_prime2));
													OPENSSL_free(outs);

													privRsa = RSA_new();
													if(rsautil_quickimport(privRsa, bn_e, bn_prime1, bn_prime2, NULL))
													{
														if(rsautil_rsa_to_privkeyblob(privRsa, &pkBlob, &cbPkBlob))
														{
															kprintf(L"Let\'s save privatekey blob in %s file (for wannadecrypt or original Wana Decrypt0r 2.0...)\n", WANA_PRIKEY_FILE);
															kull_m_file_writeData(WANA_PRIKEY_FILE, pkBlob, cbPkBlob);

															if(CryptAcquireContext(&dData.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) // we'll do RSA / AES stuff
															{
																kprintf(L"Using raw user private key!\n");
																if(CryptImportKey(dData.hProv, pkBlob, cbPkBlob, 0, 0, &dData.hKey))
																{
																	kull_m_file_Find(L"c:", NULL, TRUE, 0, FALSE, file_callback_wncry, &dData);
																	CryptDestroyKey(dData.hKey);

																	kull_m_reg_delete_PendingFileRenameOperations();
																}
																else wprintf(L"ERROR: CryptImportKey: %u\n", GetLastError());
																CryptReleaseContext(dData.hProv, 0);
															}
															else PRINT_ERROR_AUTO(L"CryptAcquireContext");
															LocalFree(pkBlob);
														}
														else PRINT_ERROR(L"OpenSSL don\'t want to convert it to MS PRIVATEKEYBLOB format\n");
													}
													else PRINT_ERROR(L"OpenSSL say us this private keys is not valid ?\n");
													RSA_free(privRsa);
												}
											}
										}
									}
									LocalFree(buffer);
								}
							}
						}
					}
					if(!found)
						PRINT_ERROR(L"Unfortunately, no correct privatekey in memory :(\n");
					CloseHandle(hProcess);
				}
				else PRINT_ERROR_AUTO(L"OpenProcess");
				BN_free(bn_e);
				BN_free(bn_modulus);
			}
			BN_CTX_end(ctx);
			BN_CTX_free(ctx);
			free(fPub);
		}
	}
	else PRINT_ERROR(L"Process not found...\n");
	return 0;
}

const PCWCHAR proc[] = {L"wnry.exe", L"wcry.exe", L"data_1.exe", L"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe", L"tasksche.exe"};
DWORD findProcess()
{
	DWORD i, p = 0;
	for (i = 0, p = 0; i < ARRAYSIZE(proc); i++)
	{
		if(kull_m_process_getProcessIdForName(proc[i], &p))
		{
			kprintf(L"Process %s found with PID: %u\n", proc[i], p);
			break;
		}
	}
	return p;
}

BOOL CALLBACK file_callback_wncry(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	BOOL status = FALSE;
	PDECRYPT_DATA pData = (PDECRYPT_DATA) pvArg;
	PWSTR ext = PathFindExtension(path);
	if(ext && (_wcsicmp(ext, WANA_FILE_EXT) == 0))
		rsautil_decryptFileWithKey(pData->hProv, pData->hKey, (LPWSTR) fullpath);
	return status;
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