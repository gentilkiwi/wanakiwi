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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <math.h>

#define RSA_2048_ENC	256 // 2048 / 8
#define RSA_2048_PRIM	(RSA_2048_ENC / 2)
#define WANA_MAGIC		((ULONGLONG) 0x21595243414e4157) // WANACRY!
#define RSA_ENC_SIZE	(RSA_2048_ENC * 5)
#define RSA_DEC_SIZE	1172
#define RSA_BAD_PAD		1225

typedef struct _WANA_FORMAT {
	ULONGLONG magic;	// WANA_MAGIC
	ULONG enc_keysize;	// RSA_2048_ENC
	BYTE key[RSA_2048_ENC];
	ULONG unkOperation;	// 4
	ULONGLONG qwDataSize; 
	BYTE data[ANYSIZE_ARRAY];
} WANA_FORMAT, *PWANA_FORMAT;

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

typedef struct _ENC_PRIV_KEY {
	DWORD totalBytes;
	BYTE data[ANYSIZE_ARRAY][RSA_2048_ENC];
} ENC_PRIV_KEY, *PENC_PRIV_KEY;

typedef struct _DEC_PRIV_KEY {
	DWORD totalBytes;
	BYTE data[ANYSIZE_ARRAY];
} DEC_PRIV_KEY, *PDEC_PRIV_KEY;

BOOL rsautil_is_prime_div_and_diff(BIGNUM *m, BIGNUM *p1, BIGNUM *p2);
BOOL rsautil_quickimport(RSA *rsa, BIGNUM *e_value, BIGNUM *p_value, BIGNUM *q_value, OPTIONAL BIGNUM *n_value);

BOOL rsautil_rsa_to_privkeyblob(RSA *rsa, PBYTE *blob, DWORD *cbBlob);
BOOL rsautil_pubkeyblob_to_rsa(PBYTE blob, DWORD cbBlob, RSA **rsa);
BOOL rsautil_pubkeyfile_to_new_e_n(PCWSTR filename, BIGNUM **e, BIGNUM **n);

void rsautil_decryptFileWithKey(HCRYPTPROV hProv, HCRYPTKEY hUserRsaKey, LPWSTR filename);

DOUBLE rsautil_normalizedEntropy(LPCBYTE data, DWORD len);