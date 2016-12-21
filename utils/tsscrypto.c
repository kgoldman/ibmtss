/********************************************************************************/
/*										*/
/*			     TSS Library Dependent Crypto Support		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tsscrypto.c 878 2016-12-19 19:52:56Z kgoldman $		*/
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

/* Interface to OpenSSL version 1.0 crypto library */

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

#include <tss2/tsscrypto.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

static TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
			     TPMI_ALG_HASH hashAlg);

static TPM_RC TSS_bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes);


/*
  Initialization
*/

TPM_RC TSS_Crypto_Init()
{
    TPM_RC		rc = 0;
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms();
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

/* On call, digest->hashAlg is the desired hash algorithm

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				const TPM2B_KEY *hmacKey,
				va_list ap)
{
    TPM_RC		rc = 0;
    int 		irc = 0;
    int			done = FALSE;
    const EVP_MD 	*md;	/* message digest method */
#if OPENSSL_VERSION_NUMBER < 0x10100000
    HMAC_CTX 		ctx;
#else
    HMAC_CTX 		*ctx;
#endif
    int			length;
    uint8_t 		*buffer;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000
    HMAC_CTX_init(&ctx);
#else
    ctx = HMAC_CTX_new();
#endif
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	irc = HMAC_Init_ex(&ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key */
			   md,					/* message digest method */
			   NULL);
#else
	irc = HMAC_Init_ex(ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key */
			   md,					/* message digest method */
			   NULL);
#endif
	
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
#if OPENSSL_VERSION_NUMBER < 0x10100000
		irc = HMAC_Update(&ctx, buffer, length);
#else
		irc = HMAC_Update(ctx, buffer, length);
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x10100000
	irc = HMAC_Final(&ctx, (uint8_t *)&digest->digest, NULL);
#else
	irc = HMAC_Final(ctx, (uint8_t *)&digest->digest, NULL);
#endif
	if (irc == 0) {
	    rc = TSS_RC_HMAC;
	}
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif
    return rc;
}

/*
  valist is int length, unsigned char *buffer pairs
  
  length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
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

/*
  RSA functions
*/

/* TSS_RSAGeneratePublicToken() generates an RSA key token from n and e
 */

TPM_RC TSS_RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				  const unsigned char *narr,    /* public modulus */
				  uint32_t nbytes,
				  const unsigned char *earr,    /* public exponent */
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
        rc = TSS_bin2bn(&e, earr, ebytes);	/* freed by caller */
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
        (*rsa_pub_key)->n = n;
        (*rsa_pub_key)->e = e;
        (*rsa_pub_key)->d = NULL;
#else
	int irc = RSA_set0_key(*rsa_pub_key, n, e, NULL);
	if (irc != 1) {
            if (tssVerbose) printf("TSS_RSAGeneratePublicToken: Error in RSA_set0_key()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
#endif
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

TPM_RC TSS_AES_GetEncKeySize(size_t *tssSessionEncKeySize)
{
    *tssSessionEncKeySize = sizeof(AES_KEY);
    return 0;
}
TPM_RC TSS_AES_GetDecKeySize(size_t *tssSessionDecKeySize)
{
    *tssSessionDecKeySize = sizeof(AES_KEY);
    return 0;
}

#define TSS_AES_KEY_BITS 128

TPM_RC TSS_AES_KeyGenerate(void *tssSessionEncKey,
			   void *tssSessionDecKey)
{
    TPM_RC		rc = 0;
    int 		irc;
    unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];
    const char 		*envKeyString = NULL;
    unsigned char 	*envKeyBin = NULL;
    size_t 		envKeyBinLen;
    
    if (rc == 0) {
	envKeyString = getenv("TPM_SESSION_ENCKEY");
    }
    if (envKeyString == NULL) {
	/* If the env variable TPM_SESSION_ENCKEY is not set, generate a random key for this
	   TSS_CONTEXT */
	if (rc == 0) {
	    rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
	}
    }
    /* The env variable TPM_SESSION_ENCKEY can set a (typically constant) encryption key.  This is
       useful for scripting, where the env variable is set to a random seed at the beginning of the
       script. */
    else {
	/* hexascii to binary */
	if (rc == 0) {
	    rc = TSS_Array_Scan(&envKeyBin, &envKeyBinLen, envKeyString);
	}
	/* range check */
	if (rc == 0) {
	    if (envKeyBinLen != AES_128_BLOCK_SIZE_BYTES) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error, env variable length %lu not %lu\n",
			   (unsigned long)envKeyBinLen, (unsigned long)sizeof(userKey));
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
	/* copy the binary to the common userKey for use below */
	if (rc == 0) {
	    memcpy(userKey, envKeyBin, envKeyBinLen);  
	}
    }
    /* translate to an openssl key token */
    if (rc == 0) {
        irc = AES_set_encrypt_key(userKey,
                                  TSS_AES_KEY_BITS,
                                  tssSessionEncKey);
	/* should never occur, null pointers or bad bit size */
	if (irc != 0) {
            if (tssVerbose)
		printf("TSS_AES_KeyGenerate: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE; 
	}
    }
    if (rc == 0) {
	irc = AES_set_decrypt_key(userKey,
				  TSS_AES_KEY_BITS,
				  tssSessionDecKey);
	/* should never occur, null pointers or bad bit size */
	if (irc != 0) {
            if (tssVerbose)
		printf("TSS_AES_KeyGenerate: Error setting openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE; 
	}
    }
    free(envKeyBin);
    return rc;
}

/* TSS_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to 'encrypt_data' using CBC.
   This function uses the session encryption key for encrypting session state.

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/
   
TPM_RC TSS_AES_Encrypt(void *tssSessionEncKey,
		       unsigned char **encrypt_data,   		/* output, caller frees */
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
                        tssSessionEncKey,
                        ivec,
                        AES_ENCRYPT);
    }
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

/* TSS_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to 'decrypt_data' using CBC.
   This function uses the session encryption key for decrypting session state.

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

TPM_RC TSS_AES_Decrypt(void *tssSessionDecKey,
		       unsigned char **decrypt_data,   		/* output, caller frees */
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
                        tssSessionDecKey,
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

TPM_RC TSS_AES_EncryptCFB(uint8_t	*dOut,		/* OUT: the encrypted */
			  uint32_t	keySizeInBits,	/* IN: key size in bit */
			  uint8_t 	*key,           /* IN: key buffer. The size of this buffer
							   in */
			  uint8_t 	*iv,		/* IN/OUT: IV for decryption */
			  uint32_t	dInSize,       	/* IN: data size */
			  uint8_t 	*dIn)		/* IN: data buffer */
{
    TPM_RC	rc = 0;
    int 	irc;
    int		blockSize;
    AES_KEY	aeskey;
    int32_t	dSize;         /* signed version of dInSize */
    
    /* Create AES encryption key token */
    if (rc == 0) {
	irc = AES_set_encrypt_key(key, keySizeInBits, &aeskey);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_EncryptCFB: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;  /* should never occur, null pointers or bad bit size */
	}
    }
    if (rc == 0) {
	/* Encrypt the current IV into the new IV, XOR in the data, and copy to output */
	for(dSize = (INT32)dInSize ; dSize > 0 ; dSize -= 16, dOut += 16, dIn += 16) {
	    /* Encrypt the current value of the IV to the intermediate value.  Store in old iv,
	       since it's not needed anymore. */
	    AES_encrypt(iv, iv, &aeskey);
	    blockSize = (dSize < 16) ? dSize : 16;	/* last block can be < 16 */	
	    TSS_XOR(dOut, dIn, iv, blockSize);
	    memcpy(iv, dOut, blockSize);
	}
    }
    return rc;
}

TPM_RC TSS_AES_DecryptCFB(uint8_t *dOut,          	/* OUT: the decrypted data */
			  uint32_t keySizeInBits, 	/* IN: key size in bit */
			  uint8_t *key,           	/* IN: key buffer. The size of this buffer
							   in */
			  uint8_t *iv,            	/* IN/OUT: IV for decryption. */
			  uint32_t dInSize,       	/* IN: data size */
			  uint8_t *dIn)			/* IN: data buffer */
{
    TPM_RC	rc = 0;
    int 	irc;
    uint8_t	tmp[16];
    int		blockSize;
    AES_KEY	aesKey;
    int32_t	dSize;
    
    /* Create AES encryption key token */
    if (rc == 0) {
	irc = AES_set_encrypt_key(key, keySizeInBits, &aesKey);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_DecryptCFB: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;  /* should never occur, null pointers or bad bit size */
	}
    }
    if (rc == 0) {
	for (dSize = (INT32)dInSize ; dSize > 0; dSize -= 16, dOut += 16, dIn += 16) {
	    /* Encrypt the IV into the temp buffer */
	    AES_encrypt(iv, tmp, &aesKey);
	    blockSize = (dSize < 16) ? dSize : 16;	/* last block can be < 16 */	
	    TSS_XOR(dOut, dIn, tmp, blockSize);
	    memcpy(iv, dIn, blockSize);
	}
    }
    return rc;
}

