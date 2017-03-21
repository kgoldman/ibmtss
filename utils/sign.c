/********************************************************************************/
/*										*/
/*			    Sign						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sign.c 945 2017-02-27 23:24:31Z kgoldman $			*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsscryptoh.h>
#include <tss2/tsscrypto.h>
#include <tss2/Unmarshal_fp.h>

static void printUsage(void);
static TPM_RC RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				     unsigned char *narr,
				     uint32_t nbytes,
				     unsigned char *earr,
				     uint32_t ebytes);
static TPM_RC RSAVerify(unsigned char *message,
			unsigned int messageSize,
			unsigned char *signature,
			unsigned int signatureSize,
			RSA *rsa_pub_key,
			int nid);
static TPM_RC RSAVerifyPEM(unsigned char *message,
			   unsigned int messageSize,
			   unsigned char *signature,
			   unsigned int signatureSize,
			   RSA *rsa_pub_key,
			   int nid,
			   const char *pemFilename);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Sign_In 			in;
    Sign_Out 			out;
    TPMI_DH_OBJECT		keyHandle = 0;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    int 			nid = NID_sha256;
    TPMI_ALG_SIG_SCHEME		scheme = TPM_ALG_RSASSA;
    const char			*messageFilename = NULL;
    const char			*ticketFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*pemFilename = NULL;
    const char			*signatureFilename = NULL;
    const char			*keyPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
 
    unsigned char 		*data = NULL;	/* message */
    size_t 			length;
    uint32_t           		sizeInBytes;	/* hash algorithm mapped to size */
    TPMT_HA 			digest;		/* digest of the message */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		    nid = NID_sha1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		    nid = NID_sha256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		    nid = NID_sha384;
		}
		else {
		    printf("Bad parameter for -halg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    scheme = TPM_ALG_RSASSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    scheme = TPM_ALG_ECDSA;
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		messageFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemFilename = argv[i];
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-tk") == 0) {
	    i++;
	    if (i < argc) {
		ticketFilename = argv[i];
	    }
	    else {
		printf("-tk option needs a value\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-os") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-os option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (messageFilename == NULL) {
	printf("Missing message file name -if\n");
	printUsage();
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&data,     /* must be freed by caller */
				     &length,
				     messageFilename);
    }
    /* hash the file */
    if (rc == 0) {
	digest.hashAlg = halg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	rc = TSS_Hash_Generate(&digest,
			       length, data,
			       0, NULL);
    }
    if (rc == 0) {
	/* Handle of key that will perform signing */
	in.keyHandle = keyHandle;

	/* digest to be signed */
	in.digest.t.size = sizeInBytes;
	memcpy(&in.digest.t.buffer, (uint8_t *)&digest.digest, sizeInBytes);
	/* Table 145 - Definition of TPMT_SIG_SCHEME inscheme */
	in.inScheme.scheme = scheme;
	/* Table 144 - Definition of TPMU_SIG_SCHEME details > */
	/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	if (scheme == TPM_ALG_RSASSA) {
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else {
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
    }
    if (rc == 0) {
	if (ticketFilename == NULL) {
	    /* proof that digest was created by the TPM (NULL ticket) */
	    /* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */
	    in.validation.tag = TPM_ST_HASHCHECK;
	    in.validation.hierarchy = TPM_RH_NULL;
	    in.validation.digest.t.size = 0;
	}
	else {
	    rc = TSS_File_ReadStructure(&in.validation,
					(UnmarshalFunction_t)TPMT_TK_HASHCHECK_Unmarshal,
					ticketFilename);
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Sign,
			 sessionHandle0, keyPassword, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal,
				     signatureFilename);
    }
    /* if a public key was specified, use openssl to verify the signature using an openssl RSA
       format key token */
    if (publicKeyFilename != NULL) {
	TPM2B_PUBLIC 	public;
	RSA         	*rsa_pub_key = NULL;
	if (rc == 0) {
	    rc = TSS_File_ReadStructure(&public,
					(UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
					publicKeyFilename);
	}
	/* construct the OpenSSL public key object */
	if (rc == 0) {
	    unsigned char earr[3] = {0x01, 0x00, 0x01};
	    rc = RSAGeneratePublicToken(&rsa_pub_key,				/* freed @1 */
					public.publicArea.unique.rsa.t.buffer, /* public modulus */
					public.publicArea.unique.rsa.t.size,
					earr,      				/* public exponent */
					sizeof(earr));
	}
	/* construct an openssl RSA public key token */
	if (rc == 0) {
	    /* public exponent */
	    rc = RSAVerify((uint8_t *)&in.digest.t.buffer,
			   in.digest.t.size,
			   (uint8_t *)&out.signature.signature.rsassa.sig.t.buffer,
			   out.signature.signature.rsassa.sig.t.size,
			   rsa_pub_key,
			   nid);
	}
	/* if a PEM file was also specified, use openssl to verify the signature using a PEM
	   format key token.  This simulates remote verification where the public key is transported
	   in PEM format. */
	if (rc == 0) {
	    if (pemFilename != NULL) {
		rc = RSAVerifyPEM((uint8_t *)&in.digest.t.buffer,
				  in.digest.t.size,
				  (uint8_t *)&out.signature.signature.rsassa.sig.t.buffer,
				  out.signature.signature.rsassa.sig.t.size,
				  rsa_pub_key,
				  nid,
				  pemFilename);
	    }
	}
	/* the PEM call frees the RSA key token */
	if (pemFilename == NULL) {
	    if (rsa_pub_key != NULL) {
		RSA_free(rsa_pub_key);          /* @1 */
	    }
	}
    }
    free(data);
    if (rc == 0) {
	if (verbose) printf("sign: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("sign: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}
    
/* bin2bn() wraps the openSSL function in a TPM error handler

   Converts a char array to bignum

   bn must be freed by the caller.
*/

static TPM_RC bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes)
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
            printf("bin2bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

/* TSS_RSAGeneratePublicToken() generates an RSA key token from n and e
 */

static TPM_RC RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				     unsigned char *narr,      	/* public modulus */
				     uint32_t nbytes,
				     unsigned char *earr,      	/* public exponent */
				     uint32_t ebytes)
{
    TPM_RC  	rc = 0;
    BIGNUM *    n = NULL;
    BIGNUM *    e = NULL;

    /* sanity check for the free */
    if (rc == 0) {
	if (*rsa_pub_key != NULL) {
            if (verbose)
		printf("RSAGeneratePublicToken: Error (fatal), token %p should be NULL\n",
		       *rsa_pub_key );
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* construct the OpenSSL RSA key object */
    if (rc == 0) {
        *rsa_pub_key = RSA_new();                        	/* freed by caller */
        if (*rsa_pub_key == NULL) {
            if (verbose) printf("RSAGeneratePublicToken: Error in RSA_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
        }
    }
    if (rc == 0) {
        rc = bin2bn(&n, narr, nbytes);	/* freed by caller */
    }
    if (rc == 0) {
        rc = bin2bn(&e, earr, ebytes);	/* freed by caller */
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
        (*rsa_pub_key)->n = n;
	(*rsa_pub_key)->e = e;
        (*rsa_pub_key)->d = NULL;

#else
	int irc = RSA_set0_key(*rsa_pub_key, n, e, NULL);
	if (irc != 1) {
            if (verbose) printf("RSAGeneratePublicToken: Error in RSA_set0_key()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
#endif
    }
    return rc;
}

/* RSAVerify() uses the low level openssl API to verify signaure over the message digest using
   the supplied public key.
*/

static TPM_RC RSAVerify(unsigned char *message,
			unsigned int messageSize,
			unsigned char *signature,
			unsigned int signatureSize,
			RSA *rsa_pub_key,
			int nid)
{
    TPM_RC  	rc = 0;
    int         irc;
    
    if (verbose) printf("RSAVerify:\n");
    if (rc == 0) {
	irc = RSA_verify(nid,
			 message, messageSize,
			 signature, signatureSize,
			 rsa_pub_key);
	if (verbose) printf("RSAVerify: RSA_verify rc %d\n", irc);
	if (irc != 1) {
	    printf("RSAVerify: Bad signature\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	    
	}
    }
    return rc;
}

static TPM_RC RSAVerifyPEM(unsigned char *message,
			   unsigned int messageSize,
			   unsigned char *signature,
			   unsigned int signatureSize,
			   RSA *rsa_pub_key,
			   int nid,
			   const char *pemFilename)
{
    TPM_RC  	rc = 0;
    int         irc;
    EVP_PKEY 	*pkey = NULL;          	/* OpenSSL public key, EVP format */
    FILE 	*pemFile = NULL;   	/* PEM file for public key */
    
    if (verbose) printf("RSAVerifyPEM:\n");
    /* save the public key to PEM format.  This simulates what would normally be the transport of
       the key to the verifier. */
    if (rc == 0) {
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("RSAVerifyPEM: EVP_PKEY failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc  = EVP_PKEY_assign_RSA(pkey, rsa_pub_key);
	if (irc == 0) {
	    printf("RSAVerifyPEM: EVP_PKEY_assign_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
	    
    }
    if (rc == 0) {
	pemFile = fopen(pemFilename, "wb");
	if (pemFile == NULL) {
	    printf("RSAVerifyPEM: Unable to open PEM file %s for write\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	irc = PEM_write_PUBKEY(pemFile, pkey);
	if (irc == 0) {
	    printf("RSAVerifyPEM: Unable to write PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);
	pemFile = NULL;
    }
    if (pkey != NULL) {
	EVP_PKEY_free(pkey);
	pkey = NULL;
    }
    /* since EVP_PKEY_free appears to free the RSA key token, add this so this call always frees the
       token, even on error */
    else {
	if (rsa_pub_key != NULL) {
	    RSA_free(rsa_pub_key);          /* @1 */
	}
    }
    rsa_pub_key = NULL;							\
    /* read the public key from PEM format.  This simulates what would normally be done after
       transport to the verifier. */
    if (rc == 0) {
	pemFile = fopen(pemFilename, "rb");
	if (pemFile == NULL) {
	    printf("RSAVerifyPEM: Unable to open PEM file %s for read\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	pkey = PEM_read_PUBKEY(pemFile, NULL, NULL, NULL);
	if (pkey == NULL) {
	    printf("RSAVerifyPEM: Unable to read PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_READ;
	}
    }
    if (rc == 0) {
	rsa_pub_key = EVP_PKEY_get1_RSA(pkey);
	if (rsa_pub_key == NULL) {
	    printf("RSAVerifyPEM: EVP_PKEY_get1_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = RSA_verify(nid,
			 message, messageSize,
			 signature, signatureSize,
			 rsa_pub_key);
	if (verbose) printf("RSAVerifyPEM: RSA_verify rc %d\n", irc);
	if (irc != 1) {
	    printf("RSAVerifyPEM: Bad signature\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	    
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);
	pemFile = NULL;
    }
    if (pkey != NULL) {
	EVP_PKEY_free(pkey);
	pkey = NULL;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("sign\n");
    printf("\n");
    printf("Runs TPM2_Sign\n");
    printf("\n");
    printf("\t-hk key handle\n");
    printf("\t[-pwdk password for key (default empty)]\n");
    printf("\t[-halg [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-rsa (default RSASSA scheme)]\n");
    printf("\t[-ecc (ECDSA scheme)]\n");
    printf("\t\tVerify only supported for RSA now\n");
    printf("\t-if input message to hash and sign\n");
    printf("\t[-ipu public key file name to verify signature (default no verify)]\n");
    printf("\t[-ipem public key PEM format file name to verify signature (default no verify)]\n");
    printf("\t\trequires -ipu\n");
    printf("\t\tThis program writes the PEM file.  It is not supplied as an input\n");
    printf("\t[-os signature file name]\n");
    printf("\t[-tk ticket file name]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t\t01 continue\n");
    exit(1);	
}
