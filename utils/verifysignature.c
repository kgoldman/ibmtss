/********************************************************************************/
/*										*/
/*			    VerifySignature					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: verifysignature.c 945 2017-02-27 23:24:31Z kgoldman $	*/
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

#include <openssl/ecdsa.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscryptoh.h>
#include <tss2/tsscrypto.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssresponsecode.h>

static void printUsage(void);
TPM_RC rawUnmarshal(TPMT_SIGNATURE *target,
		    TPMI_ALG_PUBLIC algPublic,
		    TPMI_ALG_HASH halg,
		    uint8_t *buffer, size_t length);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    VerifySignature_In 		in;
    VerifySignature_Out 	out;
    TPMI_DH_OBJECT		keyHandle = 0;
    const char			*signatureFilename = NULL;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    const char			*messageFilename = NULL;
    int				doHash = TRUE;
    const char			*ticketFilename = NULL;
    int				raw = FALSE;	/* default TPMT_SIGNATURE */
 
    unsigned char 		*data = NULL;	/* message */
    size_t 			dataLength;
    uint8_t			*buffer = NULL;		/* for the free */
    uint8_t			*buffer1 = NULL;	/* for marshaling */
    size_t 			length = 0;
    uint32_t           		sizeInBytes;	/* hash algorithm mapped to size */           		
    TPMT_HA 			digest;		/* digest of the message */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1"); 

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
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
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
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
	else if (strcmp(argv[i],"-ih") == 0) {
	    i++;
	    if (i < argc) {
		messageFilename = argv[i];
		doHash = FALSE;
	    }
	    else {
		printf("-ih option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-is") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-is option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-raw") == 0) {
	    raw = TRUE;
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
    if (keyHandle == 0) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (messageFilename == NULL) {
	printf("Missing message file name -if or hash file name -ih\n");
	printUsage();
    }
    if (signatureFilename == NULL) {
	printf("Missing signature parameter -is\n");
	printUsage();
    }
    if (rc == 0) {
       rc = TSS_File_ReadBinaryFile(&data,     /* must be freed by caller */
				    &dataLength,
				    messageFilename);
    }
    /* hash the file */
    if (rc == 0) {
	if (doHash) {
	    if (rc == 0) {
		if (verbose) printf("verifysignature: Hashing message file %s\n", messageFilename);
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		rc = TSS_Hash_Generate(&digest,
				       dataLength, data,
				       0, NULL);
	    }
	    if (rc == 0) {
		if (verbose) printf("verifysignature: Hashing message\n");
		/* digest to be verified */
		in.digest.t.size = sizeInBytes;
		memcpy(&in.digest.t.buffer, (uint8_t *)&digest.digest, sizeInBytes);
	    }
	}
	else {
	    if (verbose) printf("verifysignature: Using hash input file %s\n", messageFilename);
	    in.digest.t.size = dataLength;
	    memcpy(&in.digest.t.buffer, (uint8_t *)data, dataLength);
	}
	if (verbose) TSS_PrintAll("verifysignature: hash",
				  (uint8_t *)&in.digest.t.buffer, in.digest.t.size);
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* must be freed by caller */
				     &length,
				     signatureFilename);
    }
    if (rc == 0) {
	if (!raw) {
	    int32_t ilength = length;
	    buffer1 = buffer;
	    rc = TPMT_SIGNATURE_Unmarshal(&in.signature, &buffer1, &ilength, NO);
	}
	else {
	    rc = rawUnmarshal(&in.signature, algPublic, halg, buffer, length);
	}
    }
    free(buffer);
    buffer = NULL;
    if (rc == 0) {
	/* Handle of key that will perform verifying */
	in.keyHandle = keyHandle;
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
			 TPM_CC_VerifySignature,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (ticketFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.validation,
				     (MarshalFunction_t)TSS_TPMT_TK_VERIFIED_Marshal,
				     ticketFilename);
    }
    free(buffer);
    free(data);
    if (rc == 0) {
	if (verbose) printf("verifysignature: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("verifysignature: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* rawUnmarshal() unmarshals a raw openssl signature 'buffer' into the TPMT_SIGNATURE structure.

   It handles RSA and ECC P256.
*/

TPM_RC rawUnmarshal(TPMT_SIGNATURE *target,
		    TPMI_ALG_PUBLIC algPublic,
		    TPMI_ALG_HASH halg,
		    uint8_t *buffer, size_t length)
{
    TPM_RC			rc = 0;
    const BIGNUM *pr;
    const BIGNUM *ps;
    
    if (algPublic == TPM_ALG_RSA) {
	target->sigAlg = TPM_ALG_RSASSA;
	target->signature.rsassa.hash = halg;
	target->signature.rsassa.sig.t.size = length;
	memcpy(&target->signature.rsassa.sig.t.buffer, buffer, length);
    }
    /* TPM_ALG_ECC, the raw signature is DER encoded R and S elements */
    else {
	ECDSA_SIG* ecSig = NULL;
	int rBytes;
	int sBytes;
	if (rc == 0) {
	    target->sigAlg = TPM_ALG_ECDSA;
	    target->signature.ecdsa.hash = halg;
	}
	if (rc == 0) {
	    const unsigned char *tmpPtr = buffer;	/* because pointer moves */
	    /* convert DER to ECDSA_SIG */
	    ecSig = d2i_ECDSA_SIG(NULL, &tmpPtr, length);	/* freed @1 */
	}
	/* check that the signature size agrees with the currently hard coded P256 curve */
	if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	    pr = ecSig->r;
	    ps = ecSig->s;
#else
	    ECDSA_SIG_get0(ecSig, &pr, &ps);
#endif
	    rBytes = BN_num_bytes(pr);
	    sBytes = BN_num_bytes(ps);
	    if ((rBytes > 32) ||
		(sBytes > 32)) {
		printf("rawUnmarshal: signature rBytes %u or sBytes %u greater than 32\n",
		       rBytes, sBytes);
		rc = TPM_RC_VALUE;
	    }
	}
	/* extract the raw signature bytes from the openssl structure BIGNUMs */
	if (rc == 0) {
	    target->signature.ecdsa.signatureR.t.size = rBytes;
	    target->signature.ecdsa.signatureS.t.size = sBytes;

	    BN_bn2bin(pr, (unsigned char *)&target->signature.ecdsa.signatureR.t.buffer);
	    BN_bn2bin(ps, (unsigned char *)&target->signature.ecdsa.signatureS.t.buffer);
	    if (verbose) {
		TSS_PrintAll("rawUnmarshal: signature R",
			     target->signature.ecdsa.signatureR.t.buffer,
			     target->signature.ecdsa.signatureR.t.size);		
		TSS_PrintAll("rawUnmarshal: signature S",
			     target->signature.ecdsa.signatureS.t.buffer,
			     target->signature.ecdsa.signatureS.t.size);		
	    }
	}
	if (ecSig != NULL) {
	    ECDSA_SIG_free(ecSig);		/* @1 */
	}
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("verifysignature\n");
    printf("\n");
    printf("Runs TPM2_VerifySignature\n");
    printf("\n");
    printf("\t-hk key handle\n");
    printf("\t[-halg [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[asymmetric key algorithm]\n");
    printf("\t\t[-rsa (default)]\n");
    printf("\t\t[-ecc curve (P256)]\n");
    printf("\t-if input message file name\n");
    printf("\t-ih input hash file name\n");
    printf("\t-is signature file name\n");
    printf("\t[-raw (flag) signature specified by -is is in raw format]\n");
    printf("\t\t(default TPMT_SIGNATURE)\n");
    printf("\t[-tk ticket file name]\n");
    exit(1);	
}
