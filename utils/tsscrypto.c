/********************************************************************************/
/*										*/
/*			     TSS Crypto Support					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tsscrypto.c 683 2016-07-15 20:53:46Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <string.h>
#include <stdio.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include <tss2/tssresponsecode.h>
#include <tss2/tssutils.h>
#include <tss2/tssprint.h>
#include <tss2/tsserror.h>
#include <tss2/CpriHash_fp.h>

#include <tss2/tsscrypto.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

static TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
			     TPMI_ALG_HASH hashAlg);
static TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,
				       const TPM2B_KEY *hmacKey,
				       va_list ap);
static TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,
				       va_list ap);

static TPM_RC TSS_MGF1(unsigned char       	*mask,
		       uint32_t            	maskLen,
		       const unsigned char 	*mgfSeed,
		       uint16_t			mgfSeedlen,
		       TPMI_ALG_HASH 		halg);
static TPM_RC TSS_RSA_padding_add_PKCS1_OAEP(unsigned char *em, uint32_t emLen,
					     const unsigned char *from, uint32_t fLen,
					     const unsigned char *p,
					     int plen,
					     TPMI_ALG_HASH halg);	
static void TSS_XOR(unsigned char *out,
		    const unsigned char *in1,
		    const unsigned char *in2,
		    size_t length);

static TPM_RC TSS_bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes);


/*
  Initialization
*/

TPM_RC TSS_Crypto_Init()
{
    TPM_RC		rc = 0;
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms();
    rc = TSS_AES_KeyGenerate();
    return rc;
}

/*
  Digests
*/

static TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
			     TPMI_ALG_HASH hashAlg)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	switch (hashAlg) {
#ifdef TPM_ALG_SHA1
	  case TPM_ALG_SHA1:
	    *md = EVP_get_digestbyname("sha1");
	    break;
#endif
#ifdef TPM_ALG_SHA256	
	  case TPM_ALG_SHA256:
	    *md = EVP_get_digestbyname("sha256");
	    break;
#endif
#ifdef TPM_ALG_SHA384
	  case 	TPM_ALG_SHA384:
	    *md = EVP_get_digestbyname("sha384");
	    break;
#endif
#ifdef TPM_ALG_SHA512
	  case 	TPM_ALG_SHA512:
	    *md = EVP_get_digestbyname("sha512");
	    break;
#endif
	  default:
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    return rc;
}


/* TSS_HMAC_Generate() can be called directly to HMAC a list of streams.
   
   The ... arguments are a message list of the form
   int length, unsigned char *buffer
   terminated by a 0 length
*/

/* On call, digest->hashAlg is the desired hash algorithm */

TPM_RC TSS_HMAC_Generate(TPMT_HA *digest,		/* largest size of a digest */
			 const TPM2B_KEY *hmacKey,
			 ...)
{
    TPM_RC		rc = 0;
    va_list		ap;
    
    va_start(ap, hmacKey);
    rc = TSS_HMAC_Generate_valist(digest, hmacKey, ap);
    va_end(ap);
    return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   length 0 is ignored, buffer NULL terminates list.
*/

static TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				       const TPM2B_KEY *hmacKey,
				       va_list ap)
{
    TPM_RC		rc = 0;
    int 		irc = 0;
    int			done = FALSE;
    const EVP_MD 	*md;	/* message digest method */
    HMAC_CTX 		ctx;
    int			length;
    uint8_t 		*buffer;
    
    HMAC_CTX_init(&ctx);
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
    }
    if (rc == 0) {
	irc = HMAC_Init_ex(&ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key FIXME cast */
			   md,					/* message digest method */
			   NULL);
	if (irc == 0) {
	    rc = TSS_RC_HMAC;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate: Length is negative\n");
		rc = TSS_RC_HMAC;
	    }
	    else {
		irc = HMAC_Update(&ctx, buffer, length);
		if (irc == 0) {
		    if (tssVerbose) printf("TSS_HMAC_Generate: HMAC_Update failed\n");
		    rc = TSS_RC_HMAC;
		}
	    }
 	}
	else {
	    done = TRUE;
	}
    }

    if (rc == 0) {
	irc = HMAC_Final(&ctx, (uint8_t *)&digest->digest, NULL);
	if (irc == 0) {
	    rc = TSS_RC_HMAC;
	}
    }
    HMAC_CTX_cleanup(&ctx);
    return rc;
}

/* TSS_HMAC_Verify() can be called directly to check the HMAC of a list of streams.
   
   The ... arguments are a list of the form
   int length, unsigned char *buffer
   terminated by a 0 length

*/

TPM_RC TSS_HMAC_Verify(TPMT_HA *expect,
		       const TPM2B_KEY *hmacKey,
		       uint32_t sizeInBytes,
		       ...)
{
    TPM_RC		rc = 0;
    int			irc;
    va_list		ap;
    TPMT_HA 		actual;

    actual.hashAlg = expect->hashAlg;	/* algorithm for the HMAC calculation */
    va_start(ap, sizeInBytes);
    if (rc == 0) {
	rc = TSS_HMAC_Generate_valist(&actual, hmacKey, ap);
    }
    if (rc == 0) {
	irc = memcmp((uint8_t *)&expect->digest, &actual.digest, sizeInBytes);
	if (irc != 0) {
	    TSS_PrintAll("TSS_HMAC_Verify: calculated HMAC",
			 (uint8_t *)&actual.digest, sizeInBytes);
	    rc = TSS_RC_HMAC_VERIFY;
	}
    }
    va_end(ap);
    return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   ... is a list of int length, unsigned char *buffer pairs.

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate(TPMT_HA *digest,		/* largest size of a digest */
			 ...)
{
    TPM_RC	rc = 0;
    va_list	ap;
    va_start(ap, digest);
    rc = TSS_Hash_Generate_valist(digest, ap);
    va_end(ap);
    return rc;
}

/*
  valist is int length, unsigned char *buffer pairs
  
  length 0 is ignored, buffer NULL terminates list.
*/

static TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				       va_list ap)
{
    TPM_RC		rc = 0;
    int			irc = 0;
    int			done = FALSE;
    int			length;
    uint8_t 		*buffer;
    EVP_MD_CTX 		*mdctx;
    const EVP_MD 	*md;

    mdctx = EVP_MD_CTX_create();
        
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
    }
    if (rc == 0) {
	irc = EVP_DigestInit_ex(mdctx, md, NULL);
	if (irc != 1) {
	    rc = TSS_RC_HASH;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);		/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_Hash_Generate: Length is negative\n");
		rc = TSS_RC_HASH;
	    }
	    else {
		if (length != 0) {
		    EVP_DigestUpdate(mdctx, buffer, length);
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }
    if (rc == 0) {
	EVP_DigestFinal_ex(mdctx, (uint8_t *)&digest->digest, NULL);
    }
    EVP_MD_CTX_destroy(mdctx);
    return rc;
}

/* TSS_GetDigestSize() returns the digest size in bytes based on the hash algorithm.

   Returns 0 for an unknown algorithm.
*/

uint16_t TSS_GetDigestSize(TPM_ALG_ID hashAlg)
{
    uint16_t size;
    
    switch (hashAlg) {
      case TPM_ALG_SHA1:
	size = SHA1_DIGEST_SIZE;
	break;
      case TPM_ALG_SHA256:
	size = SHA256_DIGEST_SIZE;
	break;
      case TPM_ALG_SHA384:
	size = SHA384_DIGEST_SIZE;
	break;
#if 0
      case TPM_ALG_SHA512:
	size = SHA512_DIGEST_SIZE;
	break;
      case TPM_ALG_SM3_256:
	size = SM3_256_DIGEST_SIZE;
	break;
#endif
      default:
	size = 0;
    }
    return size;
}

/* TPM_MGF1() generates an MGF1 'array' of length 'arrayLen' from 'seed' of length 'seedlen'

   The openSSL DLL doesn't export MGF1 in Windows or Linux 1.0.0, so this version is created from
   scratch.
   
   Algorithm and comments (not the code) from:

   PKCS #1: RSA Cryptography Specifications Version 2.1 B.2.1 MGF1

   Prototype designed to be compatible with openSSL

   MGF1 is a Mask Generation Function based on a hash function.
   
   MGF1 (mgfSeed, maskLen)

   Options:     

   Hash hash function (hLen denotes the length in octets of the hash 
   function output)

   Input:
   
   mgfSeed         seed from which mask is generated, an octet string
   maskLen         intended length in octets of the mask, at most 2^32(hLen)

   Output:      
   mask            mask, an octet string of length l; or "mask too long"

   Error:          "mask too long'
*/

static TPM_RC TSS_MGF1(unsigned char       	*mask,
		       uint32_t            	maskLen,
		       const unsigned char 	*mgfSeed,
		       uint16_t			mgfSeedlen,
		       TPMI_ALG_HASH 		halg)
{
    TPM_RC 		rc = 0;
    unsigned char       counter[4];     /* 4 octets */
    uint32_t	        count;          /* counter as an integral type */
    uint32_t		outLen;
    TPMT_HA 		digest;
    uint16_t 		digestSize = TSS_GetDigestSize(halg);
    
    digest.hashAlg = halg;
    
#if 0
    if (rc == 0) {
        /* this is possible with arrayLen on a 64 bit architecture, comment to quiet beam */
        if ((maskLen / TPM_DIGEST_SIZE) > 0xffffffff) {        /* constant condition */
            if (tssVerbose) printf("TSS_MGF1: Error (fatal), Output length too large for 32 bit counter\n");
            rc = TPM_FAIL;              /* should never occur */
        }
    }
#endif
    /* 1.If l > 2^32(hLen), output "mask too long" and stop. */
    /* NOTE Checked by caller */
    /* 2. Let T be the empty octet string. */
    /* 3. For counter from 0 to [masklen/hLen] - 1, do the following: */
    for (count = 0, outLen = 0 ; (rc == 0) && (outLen < maskLen) ; count++) {
	/* a. Convert counter to an octet string C of length 4 octets - see Section 4.1 */
	/* C = I2OSP(counter, 4) NOTE Basically big endian */
        uint32_t count_n = htonl(count);
	memcpy(counter, &count_n, 4);
	/* b.Concatenate the hash of the seed mgfSeed and C to the octet string T: */
	/* T = T || Hash (mgfSeed || C) */
	/* If the entire digest is needed for the mask */
	if ((outLen + digestSize) < maskLen) {
	    rc = TSS_Hash_Generate(&digest,
				   mgfSeedlen, mgfSeed,
				   4, counter,
				   0, NULL);
	    memcpy(mask + outLen, &digest.digest, digestSize);
	    outLen += digestSize;
	}
	/* if the mask is not modulo TPM_DIGEST_SIZE, only part of the final digest is needed */
	else {
	    /* hash to a temporary digest variable */
	    rc = TSS_Hash_Generate(&digest,
				   mgfSeedlen, mgfSeed,
				   4, counter,
				   0, NULL);
	    /* copy what's needed */
	    memcpy(mask + outLen, &digest.digest, maskLen - outLen);
	    outLen = maskLen;           /* outLen = outLen + maskLen - outLen */
	}
    }
    /* 4.Output the leading l octets of T as the octet string mask. */
    return rc;
}

/*
  OAEP Padding 
*/

/* TSS_RSA_padding_add_PKCS1_OAEP() is a variation of the the openSSL function

   int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
   unsigned char *f, int fl, unsigned char *p, int pl);

   It is used because the openssl function is hard coded to SHA1.

   This function was independently written from the PKCS1 specification "9.1.1.1 Encoding
   Operation" and PKCS#1 v2.2, intended to be unencumbered by any license.


   | <-			  emLen					   -> |
   
                         |  lHash |    PS     | 01 |  Message	      |

                            SHA                       flen

                         |  db                                        |
			 |  dbMask                                    |
        |  seed          |

	   SHA
	   
        |  seedMask      | 
   | 00 |  maskSeed      |   maskedDB                                 |
*/

TPM_RC TSS_RSA_padding_add_PKCS1_OAEP(unsigned char *em, uint32_t emLen,
				      const unsigned char *from, uint32_t fLen,
				      const unsigned char *p,
				      int plen,
				      TPMI_ALG_HASH halg)	
{	
    TPM_RC		rc = 0;
    TPMT_HA 		lHash;
    unsigned char 	*db;
    
    unsigned char *dbMask = NULL;			/* freed @1 */
    unsigned char *seed = NULL;				/* freed @2 */
    unsigned char *maskedDb;
    unsigned char *seedMask;
    unsigned char *maskedSeed;

    uint16_t hlen = TSS_GetDigestSize(halg);
    
    /* 1.a. If the length of L is greater than the input limitation for */
    /* the hash function (2^61-1 octets for SHA-1) then output "parameter */
    /* string too long" and stop. */
    if (rc == 0) {
	if (plen > 0xffff) {
	    if (tssVerbose) printf("TSS_RSA_padding_add_PKCS1_OAEP: Error, "
				   "label %u too long\n", plen);
	    rc = TSS_RC_RSA_PADDING;
	}	    
    }
    /* 1.b. If ||M|| > emLen-2hLen-1 then output "message too long" and stop. */
    if (rc == 0) {
	if (emLen < ((2 * hlen) + 2 + fLen)) {
	    if (tssVerbose) printf("TSS_RSA_padding_add_PKCS1_OAEP: Error, "
				   "message length %u too large for encoded length %u\n",
				   fLen, emLen);
	    rc = TSS_RC_RSA_PADDING;
	}
    }
    /* 2.a. Let lHash = Hash(L), an octet string of length hLen. */
    if (rc == 0) {
	lHash.hashAlg = halg;
	rc = TSS_Hash_Generate(&lHash,
			       plen, p,
			       0, NULL);
    }
    if (rc == 0) {
	/* 2.b. Generate an octet string PS consisting of emLen-||M||-2hLen-2 zero octets. The
	   length of PS may be 0. */
	/* 2.c. Concatenate lHash, PS, a single octet of 0x01 the message M, to form a data block DB
	   as: DB = lHash || PS || 01 || M */
	/* NOTE Since db is eventually maskedDb, part of em, create directly in em */
	db = em + hlen + 1;
	memcpy(db, &lHash.digest, hlen);			/* lHash */
	/* PSlen = emlen - flen - (2 * hlen) - 2 */
	memset(db + hlen, 0,					/* PS */
	       emLen - fLen - (2 * hlen) - 2);
	/* position of 0x01 in db is
	   hlen + PSlen =
	   hlen + emlen - flen - (2 * hlen) - 2 = 
	   emlen - hlen - flen - 2 */
	db[emLen - fLen - hlen - 2] = 0x01;
	memcpy(db + emLen - fLen - hlen - 1, from, fLen);	/* M */
    }
    /* 2.d. Generate a random octet string seed of length hLen. */
    if (rc == 0) {
	rc = TSS_Malloc(&seed, hlen);
    }
    if (rc == 0) {
	rc = TSS_RandBytes(seed, hlen);
    }
    if (rc == 0) {
	rc = TSS_Malloc(&dbMask, emLen - hlen - 1);
    }
    if (rc == 0) {
	/* 2.e. Let dbMask = MGF(seed, emLen-hLen-1). */
	rc = TSS_MGF1(dbMask, emLen - hlen -1,	/* dbLen */
		      seed, hlen,
		      halg);
    }
    if (rc == 0) {
	/* 2.f. Let maskedDB = DB xor dbMask. */
	/* NOTE Since maskedDB is eventually em, XOR directly to em */
	maskedDb = em + hlen + 1;
	TSS_XOR(maskedDb, db, dbMask, emLen - hlen -1);
	/* 2.g. Let seedMask = MGF(maskedDB, hLen). */
	/* NOTE Since seedMask is eventually em, create directly to em */
	seedMask = em + 1;
	rc = TSS_MGF1(seedMask, hlen,
		      maskedDb, emLen - hlen - 1,
		      halg);
    }
    if (rc == 0) {
	/* 2.h. Let maskedSeed = seed xor seedMask. */
	/* NOTE Since maskedSeed is eventually em, create directly to em */
	maskedSeed = em + 1;
	TSS_XOR(maskedSeed, seed, seedMask, hlen);
	/* 2.i. 0x00, maskedSeed, and maskedDb to form EM */
	/* NOTE Created directly in em */
    }
    free(dbMask);		/* @1 */
    free(seed);			/* @2 */
    return rc;
}

/* Random Numbers */

TPM_RC TSS_RandBytes(unsigned char *buffer, uint32_t size)
{
    TPM_RC 	rc = 0;
    int		irc = 0;

    irc = RAND_bytes(buffer, size);
    if (irc != 1) {
	if (tssVerbose) printf("TSS_RandBytes: Random number generation failed\n");
	rc = TSS_RC_RNG_FAILURE;
    }
    return rc;
}

/* TPM_XOR XOR's 'in1' and 'in2' of 'length', putting the result in 'out'

 */

static void TSS_XOR(unsigned char *out,
		    const unsigned char *in1,
		    const unsigned char *in2,
		    size_t length)
{
    size_t i;
    
    for (i = 0 ; i < length ; i++) {
	out[i] = in1[i] ^ in2[i];
    }
    return;
}

/*
  RSA functions
*/

/* TSS_RSAGeneratePublicToken() generates an RSA key token from n and e
 */

TPM_RC TSS_RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				  const unsigned char *narr,      	/* public modulus */
				  uint32_t nbytes,
				  const unsigned char *earr,      	/* public exponent */
				  uint32_t ebytes)
{
    TPM_RC  	rc = 0;
    BIGNUM *    n = NULL;
    BIGNUM *    e = NULL;

    /* sanity check for the free */
    if (rc == 0) {
	if (*rsa_pub_key != NULL) {
            if (tssVerbose)
		printf("TSS_RSAGeneratePublicToken: Error (fatal), token %p should be NULL\n",
		       *rsa_pub_key );
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* construct the OpenSSL private key object */
    if (rc == 0) {
        *rsa_pub_key = RSA_new();                        	/* freed by caller */
        if (*rsa_pub_key == NULL) {
            if (tssVerbose) printf("TSS_RSAGeneratePublicToken: Error in RSA_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
        }
    }
    if (rc == 0) {
        rc = TSS_bin2bn(&n, narr, nbytes);	/* freed by caller */
    }
    if (rc == 0) {
        (*rsa_pub_key)->n = n;
        rc = TSS_bin2bn(&e, earr, ebytes);	/* freed by caller */
    }
    if (rc == 0) {
        (*rsa_pub_key)->e = e;
        (*rsa_pub_key)->d = NULL;
    }
    return rc;
}

/* TSS_RSAPublicEncrypt() pads 'decrypt_data' to 'encrypt_data_size' and encrypts using the public
   key 'n, e'.
*/

TPM_RC TSS_RSAPublicEncrypt(unsigned char *encrypt_data,    /* encrypted data */
			    size_t encrypt_data_size,       /* size of encrypted data buffer */
			    const unsigned char *decrypt_data,      /* decrypted data */
			    size_t decrypt_data_size,
			    unsigned char *narr,           /* public modulus */
			    uint32_t nbytes,
			    unsigned char *earr,           /* public exponent */
			    uint32_t ebytes,
			    unsigned char *p,		/* encoding parameter */
			    int pl,
			    TPMI_ALG_HASH halg)		/* OAEP hash algorithm */
{
    TPM_RC  	rc = 0;
    int         irc;
    RSA         *rsa_pub_key = NULL;
    unsigned char *padded_data = NULL;
    
    if (tssVverbose) printf(" TSS_RSAPublicEncrypt: Input data size %lu\n",
			    (unsigned long)decrypt_data_size);
    /* intermediate buffer for the decrypted but still padded data */
    if (rc == 0) {
        rc = TSS_Malloc(&padded_data, encrypt_data_size);               /* freed @2 */
    }
    /* construct the OpenSSL public key object */
    if (rc == 0) {
	rc = TSS_RSAGeneratePublicToken(&rsa_pub_key,	/* freed @1 */
					narr,      	/* public modulus */
					nbytes,
					earr,      	/* public exponent */
					ebytes);
    }
    if (rc == 0) {
	padded_data[0] = 0x00;
	rc = TSS_RSA_padding_add_PKCS1_OAEP(padded_data,		/* to */
					    encrypt_data_size,		/* to length */
					    decrypt_data,		/* from */
					    decrypt_data_size,		/* from length */
					    p,		/* encoding parameter */
					    pl,		/* encoding parameter length */
					    halg);	/* OAEP hash algorithm */
    }
    if (rc == 0) {
        if (tssVverbose)
	    printf("  TSS_RSAPublicEncrypt: Padded data size %lu\n",
		   (unsigned long)encrypt_data_size);
        if (tssVverbose) TSS_PrintAll("  TPM_RSAPublicEncrypt: Padded data", padded_data,
				      encrypt_data_size);
        /* encrypt with public key.  Must pad first and then encrypt because the encrypt
           call cannot specify an encoding parameter */
	/* returns the size of the encrypted data.  On error, -1 is returned */
	irc = RSA_public_encrypt(encrypt_data_size,         /* from length */
				 padded_data,               /* from - the clear text data */
				 encrypt_data,              /* the padded and encrypted data */
				 rsa_pub_key,               /* key */
				 RSA_NO_PADDING);           /* padding */
	if (irc < 0) {
	    if (tssVerbose) printf("TSS_RSAPublicEncrypt: Error in RSA_public_encrypt()\n");
	    rc = TSS_RC_RSA_ENCRYPT;
	}
    }
    if (rc == 0) {
        if (tssVverbose) printf("  TSS_RSAPublicEncrypt: RSA_public_encrypt() success\n");
    }
    if (rsa_pub_key != NULL) {
        RSA_free(rsa_pub_key);          /* @1 */
    }
    free(padded_data);                  /* @2 */
    return rc;
}

/* TSS_bin2bn() wraps the openSSL function in a TPM error handler

   Converts a char array to bignum

   bn must be freed by the caller.
*/

static TPM_RC TSS_bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes)
{
    TPM_RC	rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    
       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            if (tssVerbose) printf("TSS_bin2bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

/*
  AES
*/

#define TSS_AES_KEY_BITS 128

static AES_KEY aes_enc_key;
static AES_KEY aes_dec_key;

TPM_RC TSS_AES_KeyGenerate()
{
    TPM_RC		rc = 0;
    int 		irc;
    unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];

    /* generate a random key */
    if (rc == 0) {
	rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
    }
    /* translate to an openssl key token */
    if (rc == 0) {
        irc = AES_set_encrypt_key(userKey,
                                  TSS_AES_KEY_BITS,
                                  &aes_enc_key);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_KeyGenerate: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;      /* should never occur, null pointers or bad bit size */
	}
    }
    if (rc == 0) {
	irc = AES_set_decrypt_key(userKey,
				  TSS_AES_KEY_BITS,
				  &aes_dec_key);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_KeyGenerate: Error setting openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;      /* should never occur, null pointers or bad bit size */
	}
    }
    return rc;
}

/* TSS_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to
   'encrypt_data'

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

   
TPM_RC TSS_AES_Encrypt(unsigned char **encrypt_data,   		/* output, caller frees */
		       uint32_t *encrypt_length,		/* output */
		       const unsigned char *decrypt_data,	/* input */
		       uint32_t decrypt_length)			/* input */
{
    TPM_RC		rc = 0;
    uint32_t		pad_length;
    unsigned char	*decrypt_data_pad;
    unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */

    decrypt_data_pad = NULL;    /* freed @1 */
    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = AES_128_BLOCK_SIZE_BYTES - (decrypt_length % AES_128_BLOCK_SIZE_BYTES);
        *encrypt_length = decrypt_length + pad_length;
         /* allocate memory for the encrypted response */
        rc = TSS_Malloc(encrypt_data, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(&decrypt_data_pad, *encrypt_length);
    }
    /* pad the decrypted clear text data */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
        /* last gets pad = pad length */
        memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* encrypt the padded input to the output */
        AES_cbc_encrypt(decrypt_data_pad,
                        *encrypt_data,
                        *encrypt_length,
                        &aes_enc_key,
                        ivec,
                        AES_ENCRYPT);
    }
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

/* TSS_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to
   'decrypt_data'

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

TPM_RC TSS_AES_Decrypt(unsigned char **decrypt_data,   		/* output, caller frees */
		       uint32_t *decrypt_length,		/* output */
		       const unsigned char *encrypt_data,	/* input */
		       uint32_t encrypt_length)			/* input */
{
    TPM_RC          	rc = 0;
    uint32_t		pad_length;
    uint32_t		i;
    unsigned char       *pad_data;
    unsigned char       ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */
    
    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < AES_128_BLOCK_SIZE_BYTES) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad length %u\n",
				   encrypt_length);
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(decrypt_data, encrypt_length);
    }
    /* decrypt the input to the padded output */
    if (rc == 0) {
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* decrypt the padded input to the output */
        AES_cbc_encrypt(encrypt_data,
                        *decrypt_data,
                        encrypt_length,
                        &aes_dec_key,
                        ivec,
                        AES_DECRYPT);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        if ((pad_length == 0) ||
            (pad_length > AES_128_BLOCK_SIZE_BYTES)) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, illegal pad length\n");
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; (rc == 0) && (i < pad_length) ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad pad %02x at index %u\n",
				       *pad_data, i);
                rc = TSS_RC_AES_DECRYPT_FAILURE;
            }
        }
    }
    return rc;
}
