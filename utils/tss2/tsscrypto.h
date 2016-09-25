/********************************************************************************/
/*										*/
/*			  TSS Crypto Support	  				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tsscrypto.h 730 2016-08-23 21:09:53Z kgoldman $		*/
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

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that need some basic crypto functions.
*/

#ifndef TSSCRYPTO_H
#define TSSCRYPTO_H

#include <stdint.h>
#include <stdio.h>

#include <openssl/rsa.h>

#ifndef TPM_TSS
#define TPM_TSS
#endif
#include <tss2/TPM_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

LIB_EXPORT
TPM_RC TSS_Crypto_Init(void);

LIB_EXPORT
TPM_RC TSS_HMAC_Generate(TPMT_HA *digest,
			 const TPM2B_KEY *hmacKey,
			 ...);
LIB_EXPORT
TPM_RC TSS_HMAC_Verify(TPMT_HA *expect,
		       const TPM2B_KEY *hmacKey,
		       UINT32 sizeInBytes,
		       ...);
LIB_EXPORT
TPM_RC TSS_Hash_Generate(TPMT_HA *digest,
			 ...);

LIB_EXPORT
uint16_t TSS_GetDigestSize(TPM_ALG_ID hashAlg);

LIB_EXPORT
TPM_RC TSS_RandBytes(unsigned char *buffer, uint32_t size);

LIB_EXPORT
TPM_RC TSS_RSAPublicEncrypt(unsigned char* encrypt_data,
			    size_t encrypt_data_size,
			    const unsigned char *decrypt_data,
			    size_t decrypt_data_size,
			    unsigned char *narr,
			    uint32_t nbytes,
			    unsigned char *earr,
			    uint32_t ebytes,
			    unsigned char *p,
			    int pl,
			    TPMI_ALG_HASH halg);
LIB_EXPORT
TPM_RC TSS_RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				  const unsigned char *narr,   	/* public modulus */
				  uint32_t nbytes,
				  const unsigned char *earr,   	/* public exponent */
				  uint32_t ebytes);

TPM_RC TSS_AES_KeyGenerate(void);
TPM_RC TSS_AES_Encrypt(unsigned char **encrypt_data,
		       uint32_t *encrypt_length,
		       const unsigned char *decrypt_data,
		       uint32_t decrypt_length);
TPM_RC TSS_AES_Decrypt(unsigned char **decrypt_data,
		       uint32_t *decrypt_length,
		       const unsigned char *encrypt_data,
		       uint32_t encrypt_length);

#ifdef __cplusplus
}
#endif

#endif
