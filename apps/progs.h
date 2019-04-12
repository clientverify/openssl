/* apps/progs.h */
/* automatically generated by progs.pl for openssl.c */

extern int s_client_main(int argc,char *argv[]);

#define FUNC_TYPE_GENERAL	1
#define FUNC_TYPE_MD		2
#define FUNC_TYPE_CIPHER	3
#define FUNC_TYPE_PKEY		4
#define FUNC_TYPE_MD_ALG	5
#define FUNC_TYPE_CIPHER_ALG	6

typedef struct {
	int type;
	const char *name;
	int (*func)(int argc,char *argv[]);
	} FUNCTION;
DECLARE_LHASH_OF(FUNCTION);

FUNCTION functions[] = {
#if !defined(OPENSSL_NO_SOCK) && !(defined(OPENSSL_NO_SSL2) && defined(OPENSSL_NO_SSL3))
	{FUNC_TYPE_GENERAL,"s_client",s_client_main},
#endif
#ifndef OPENSSL_NO_MD2
	{FUNC_TYPE_MD,"md2",dgst_main},
#endif
#ifndef OPENSSL_NO_MD4
	{FUNC_TYPE_MD,"md4",dgst_main},
#endif
#ifndef OPENSSL_NO_MD5
	{FUNC_TYPE_MD,"md5",dgst_main},
#endif
#ifndef OPENSSL_NO_SHA
	{FUNC_TYPE_MD,"sha",dgst_main},
#endif
#ifndef OPENSSL_NO_SHA1
	{FUNC_TYPE_MD,"sha1",dgst_main},
#endif
#ifndef OPENSSL_NO_MDC2
	{FUNC_TYPE_MD,"mdc2",dgst_main},
#endif
#ifndef OPENSSL_NO_RMD160
	{FUNC_TYPE_MD,"rmd160",dgst_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-128-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-128-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-192-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-192-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-256-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_AES
	{FUNC_TYPE_CIPHER,"aes-256-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-128-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-128-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-192-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-192-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-256-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{FUNC_TYPE_CIPHER,"camellia-256-ecb",enc_main},
#endif
	{FUNC_TYPE_CIPHER,"base64",enc_main},
#ifdef ZLIB
	{FUNC_TYPE_CIPHER,"zlib",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des3",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"desx",enc_main},
#endif
#ifndef OPENSSL_NO_IDEA
	{FUNC_TYPE_CIPHER,"idea",enc_main},
#endif
#ifndef OPENSSL_NO_SEED
	{FUNC_TYPE_CIPHER,"seed",enc_main},
#endif
#ifndef OPENSSL_NO_RC4
	{FUNC_TYPE_CIPHER,"rc4",enc_main},
#endif
#ifndef OPENSSL_NO_RC4
	{FUNC_TYPE_CIPHER,"rc4-40",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2",enc_main},
#endif
#ifndef OPENSSL_NO_BF
	{FUNC_TYPE_CIPHER,"bf",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast",enc_main},
#endif
#ifndef OPENSSL_NO_RC5
	{FUNC_TYPE_CIPHER,"rc5",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede3",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede3-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede3-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_DES
	{FUNC_TYPE_CIPHER,"des-ede3-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_IDEA
	{FUNC_TYPE_CIPHER,"idea-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_IDEA
	{FUNC_TYPE_CIPHER,"idea-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_IDEA
	{FUNC_TYPE_CIPHER,"idea-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_IDEA
	{FUNC_TYPE_CIPHER,"idea-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_SEED
	{FUNC_TYPE_CIPHER,"seed-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_SEED
	{FUNC_TYPE_CIPHER,"seed-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_SEED
	{FUNC_TYPE_CIPHER,"seed-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_SEED
	{FUNC_TYPE_CIPHER,"seed-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-64-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_RC2
	{FUNC_TYPE_CIPHER,"rc2-40-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_BF
	{FUNC_TYPE_CIPHER,"bf-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_BF
	{FUNC_TYPE_CIPHER,"bf-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_BF
	{FUNC_TYPE_CIPHER,"bf-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_BF
	{FUNC_TYPE_CIPHER,"bf-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast5-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast5-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast5-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast5-ofb",enc_main},
#endif
#ifndef OPENSSL_NO_CAST
	{FUNC_TYPE_CIPHER,"cast-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_RC5
	{FUNC_TYPE_CIPHER,"rc5-cbc",enc_main},
#endif
#ifndef OPENSSL_NO_RC5
	{FUNC_TYPE_CIPHER,"rc5-ecb",enc_main},
#endif
#ifndef OPENSSL_NO_RC5
	{FUNC_TYPE_CIPHER,"rc5-cfb",enc_main},
#endif
#ifndef OPENSSL_NO_RC5
	{FUNC_TYPE_CIPHER,"rc5-ofb",enc_main},
#endif
	{0,NULL,NULL}
	};
