#ifndef OPENSSL_CRYPTO_H
#define OPENSSL_CRYPTO_H

#define OPENSSL_VERSION_PTEXT "OpenSSL engine 0.9.6l"

#define EVP_MAX_MD_SIZE			(16+20) /* The SSLv3 md5+sha1 type */

#if defined( sun )		/* Newer Sparc's */
#  define DES_PTR
#  define DES_RISC1
#  define DES_UNROLL
#elif defined( __ultrix )	/* Older MIPS */
#  define DES_PTR
#  define DES_RISC2
#  define DES_UNROLL
#elif defined( __osf1__ )	/* Alpha */
#  define DES_PTR
#  define DES_RISC2
#elif defined ( _AIX )		/* RS6000 */
  /* Unknown */
#elif defined( __hpux )		/* HP-PA */
  /* Unknown */
#elif defined( __aux )		/* 68K */
  /* Unknown */
#elif defined( __dgux )		/* 88K (but P6 in latest boxes) */
#  define DES_UNROLL
#elif defined( __sgi )		/* Newer MIPS */
#  define DES_PTR
#  define DES_RISC2
#  define DES_UNROLL
#elif defined( i386 )		/* x86 boxes, should be gcc */
#  define DES_PTR
#  define DES_RISC1
#  define DES_UNROLL
#endif /* Systems-specific speed defines */

#if 0
#define EVP_MD_block_size(X) (SHA_CBLOCK)
#define EVP_DigestInit(X,Y) SHA1_Init(X)
#define EVP_DigestUpdate(X,Y,Z) SHA1_Update(X,Y,Z)
//#define EVP_DigestFinal(X,Y,Z) SHA1_Final(X,Y,Z)

typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;
typedef struct engine_st ENGINE;

struct env_md_ctx_st
	{
	  
	const EVP_MD *digest;
	ENGINE *engine; /* functional reference if 'digest' is ENGINE-provided */
	unsigned long flags;
	void *md_data;
	} /* EVP_MD_CTX */;

/* values for EVP_MD_CTX flags */

#define EVP_MD_CTX_FLAG_ONESHOT		0x0001 /* digest update will be called
						* once only */
#define EVP_MD_CTX_FLAG_CLEANED		0x0002 /* context has already been
						* cleaned */


struct env_md_st
	{
	int type;
	int pkey_type;
	int md_size;
	unsigned long flags;
	int (*init)(EVP_MD_CTX *ctx);
	int (*update)(EVP_MD_CTX *ctx,const void *data,unsigned long count);
	int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
	int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
	int (*cleanup)(EVP_MD_CTX *ctx);

	/* FIXME: prototype these some day */
	int (*sign)();
	int (*verify)();
	int required_pkey_type[5]; /*EVP_PKEY_xxx */
	int block_size;
	int ctx_size; /* how big does the ctx->md_data need to be */
	} /* EVP_MD */;

#define EVP_MD_FLAG_ONESHOT	0x0001 /* digest can only handle a single
					* block */

#endif

static inline void OPENSSL_cleanse(char *dest, int len) {
	int i;
	for(i=0; i < len; i++) {
		dest[i] = 0;
	}
}
#endif // OPENSSL_CRYPTO_H
