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
#include "rsautil.h"

/* I know I don't check all return values */
BOOL rsautil_is_prime_div_and_diff(BIGNUM *m, BIGNUM *p1, BIGNUM *p2)
{
	BOOL status = FALSE;
	BN_CTX *ctx;
	BIGNUM *r;
	ctx = BN_CTX_new();
	if(BN_is_prime_fasttest_ex(p1, 2, ctx, 0, NULL) > 0)
	{
		r = BN_new();
		BN_div(p2, r, m, p1, ctx);
		status = BN_is_zero(r);
		BN_free(r);
	}
	BN_CTX_free(ctx);
	return status;
}

BOOL rsautil_quickimport(RSA *rsa, BIGNUM *e_value, BIGNUM *p_value, BIGNUM *q_value, OPTIONAL BIGNUM *n_value)
{
	BIGNUM *r0, *r1, *r2;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);

	rsa->n = BN_new();
	rsa->d = BN_new();
	rsa->e = BN_new();
	rsa->p = BN_new();
	rsa->q = BN_new();
	rsa->dmp1 = BN_new();
	rsa->dmq1 = BN_new();
	rsa->iqmp = BN_new();

	BN_copy(rsa->e, e_value);
	BN_copy(rsa->p, p_value);
	BN_copy(rsa->q, q_value);
	if(n_value)
		BN_copy(rsa->n, n_value);
	else
		BN_mul(rsa->n, rsa->p, rsa->q, ctx);
	BN_sub(r1, rsa->p, BN_value_one());
	BN_sub(r2, rsa->q, BN_value_one());
	BN_mul(r0, r1, r2, ctx);
	BN_mod_inverse(rsa->d, rsa->e, r0, ctx);
	BN_mod(rsa->dmp1, rsa->d, r1, ctx);
	BN_mod(rsa->dmq1, rsa->d, r2, ctx);
	BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return (RSA_check_key(rsa) == 1);
}

BOOL rsautil_rsa_to_privkeyblob(RSA *rsa, PBYTE *blob, DWORD *cbBlob)
{
	BOOL status = FALSE;
	BIO *out;
	EVP_PKEY *pk;
	int ret;
	char *ptr;

	if(pk = EVP_PKEY_new())
	{
		if(out = BIO_new(BIO_s_mem()))
		{
			EVP_PKEY_set1_RSA(pk, rsa);

			ret = i2b_PrivateKey_bio(out, pk);
			if(ret > 0)
			{
				*cbBlob = BIO_get_mem_data(out, &ptr);
				if(*blob = (PBYTE) LocalAlloc(LPTR, *cbBlob))
				{
					status = TRUE;
					RtlCopyMemory(*blob, ptr, *cbBlob);
				}
			}
			else /**/;
			BIO_free(out);
		}
		EVP_PKEY_free(pk);
	}
	return status;
}

BOOL rsautil_pubkeyblob_to_rsa(PBYTE blob, DWORD cbBlob, RSA **rsa)
{
	BOOL status = FALSE;
	EVP_PKEY *pubKey;
	if(pubKey = EVP_PKEY_new())
	{
		pubKey = b2i_PublicKey(&blob, cbBlob);
		if(pubKey)
		{
			*rsa = EVP_PKEY_get1_RSA(pubKey);
			status = (*rsa != NULL);
			EVP_PKEY_free(pubKey);
		}
	}
	return status;
}

BOOL rsautil_pubkeyfile_to_new_e_n(PCWSTR filename, BIGNUM **e, BIGNUM **n)
{
	BOOL status = FALSE;
	PBYTE blob;
	DWORD cbBlob;
	RSA *rsa;

	*e = BN_new();
	*n = BN_new();

	if(kull_m_file_readData(filename, &blob, &cbBlob))
	{
		if(status = rsautil_pubkeyblob_to_rsa(blob, cbBlob, &rsa))
		{
			BN_copy(*e, rsa->e);
			BN_copy(*n, rsa->n);
			RSA_free(rsa);
		}
		LocalFree(blob);
	}
	else PRINT_ERROR_AUTO(L"fileutil_readData");

	if(!status)
	{
		BN_free(*e);
		BN_free(*n);
	}
	return status;
}

BOOL SIMPLE_kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey)
{
	BOOL status = FALSE;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;
	if(keyBlob = (PGENERICKEY_BLOB) LocalAlloc(LPTR, szBlob))
	{
		keyBlob->Header.bType = PLAINTEXTKEYBLOB;
		keyBlob->Header.bVersion = CUR_BLOB_VERSION;
		keyBlob->Header.reserved = 0;
		keyBlob->Header.aiKeyAlg = calgid;
		keyBlob->dwKeyLen = keyLen;
		RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
		status = CryptImportKey(hProv, (LPCBYTE) keyBlob, szBlob, 0, flags, hKey);
		LocalFree(keyBlob);
	}
	return status;
}

void rsautil_decryptFileWithKey(HCRYPTPROV hProv, HCRYPTKEY hUserRsaKey, LPWSTR filename)
{
	HCRYPTKEY hUserFileAesKey;
	PWANA_FORMAT pbEncData;
	PWCHAR p;
	DWORD cbEncData, cbRealDataLen, cryptoMode = CRYPT_MODE_CBC;
	kprintf(L"File %s -- ", filename);
	if(kull_m_file_readData(filename, (PBYTE *) &pbEncData, &cbEncData))
	{
		if(p = wcsrchr(filename, L'.'))
		{
			*p = L'\0'; // 'delete' the WNCRY extension
			if(pbEncData->magic == WANA_MAGIC)
			{
				if(CryptDecrypt(hUserRsaKey, 0, TRUE, 0, pbEncData->key, &pbEncData->enc_keysize)) // decrypt the raw AES key from your RSA key
				{
					if(SIMPLE_kull_m_crypto_hkey(hProv, CALG_AES_128, pbEncData->key, pbEncData->enc_keysize, 0, &hUserFileAesKey)) // let's make a AES 128 Windows key from raw bytes
					{
						if(CryptSetKeyParam(hUserFileAesKey, KP_MODE, (PBYTE) &cryptoMode, 0)) // we'll do CBC
						{
							cbRealDataLen = cbEncData - FIELD_OFFSET(WANA_FORMAT, data);
							if(CryptDecrypt(hUserFileAesKey, 0, FALSE, 0, pbEncData->data, &cbRealDataLen)) // decrypt final data (padding issue, so 'FALSE' arg)
							{
								if(kull_m_file_writeData(filename, pbEncData->data, (ULONG) pbEncData->qwDataSize))
									kprintf(L"OK\n");
								else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
							}
							else PRINT_ERROR_AUTO(L"CryptDecrypt");
						}
						CryptDestroyKey(hUserFileAesKey);
					}
				}
				else PRINT_ERROR_AUTO(L"CryptDecrypt");
			}
			else PRINT_ERROR(L"ERROR: WANACRY! magic number not found\n");
		}
		else PRINT_ERROR(L"ERROR: no \'.\' at the end of the user file ?\n");
		LocalFree(pbEncData);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_readData");
}

// so inspired by @adriengnt \o/ <== again, this guy rocks
DOUBLE rsautil_normalizedEntropy(LPCBYTE data, DWORD len)
{
	DOUBLE ret = 0.0, p;
	DWORD i, hist[256] = {0};
	for (i = 0; i < len; ++i)
		++hist[data[i]];

	for(i = 0; i < ARRAYSIZE(hist); i++)
	{
		if(hist[i])
		{
			p = (DOUBLE) hist[i] / (DOUBLE) len;
			ret += p * log(p);
		}
	}
	return (ret == 0.0) ? 0.0 : (-ret / log(256.));
}