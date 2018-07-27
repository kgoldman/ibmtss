/********************************************************************************/
/*										*/
/*			    TPM 1.2 Sign					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sign.c 1286 2018-07-27 19:20:16Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tpmstructures12.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal12_fp.h>
#include "cryptoutils.h"

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Sign12_In			in;
    Sign12_Out			out;
    TPM_KEY_HANDLE		keyHandle = 0;
    const char			*keyPassword = NULL; 
    const char			*signatureFilename = NULL;
    const char			*inputFilename = NULL;
    unsigned char 		*input = NULL;
    size_t 			inputlength;
    TPMT_HA 			areaToSign;
    const char 			*keyFilename = NULL;
    TPM_AUTHHANDLE 		sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
	
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

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
	else if (!strcmp("-pwdk",argv[i])) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		inputFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
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
	else if (strcmp(argv[i],"-ik") == 0) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    }
	    else {
		printf("-ik option needs a value\n");
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
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (inputFilename == NULL) {
	printf("Missing input filename -if\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&input,     	/* freed @1*/
				     &inputlength,
				     inputFilename);
    }
    if (rc == 0) {
	in.keyHandle = keyHandle;
	areaToSign.hashAlg = TPM_ALG_SHA1; 
	rc = TSS_Hash_Generate(&areaToSign,
			       inputlength, input,
			       0, NULL);
	memcpy(in.areaToSign, (uint8_t *)&areaToSign.digest, SHA1_DIGEST_SIZE);
	in.areaToSignSize = SHA1_DIGEST_SIZE;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_Sign,
			 sessionHandle0, keyPassword, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile((uint8_t *)out.sig, out.sigSize, signatureFilename) ;
    }
    /* if a key file was specified, verify the signature */
    if (keyFilename != NULL) {
	TPM_KEY12 	signingKey;
	RSA         	*rsaPubKey = NULL;
	TPMT_SIGNATURE 	tSignature;

	/* get the signing key */
	if (rc == 0) {
	    rc = TSS_File_ReadStructure(&signingKey,
					(UnmarshalFunction_t)TSS_TPM_KEY12_Unmarshalu,
					keyFilename);
	}
	/* construct the OpenSSL RSA public key token */
	if (rc == 0) {
	    unsigned char earr[3] = {0x01, 0x00, 0x01};
	    rc = TSS_RSAGeneratePublicToken
		 (&rsaPubKey,			/* freed @3 */
		  signingKey.pubKey.key,	 	/* public modulus */
		  signingKey.pubKey.keyLength,
		  earr,      			/* public exponent */
		  sizeof(earr));
	}
	if (rc == 0) {
	    rc = convertRsaBinToTSignature(&tSignature,
					   TPM_ALG_SHA1,
					   out.sig,
					   out.sigSize);
	}
	/* verify the TPM signature */
	if (rc == 0) {
	    rc = verifyRSASignatureFromRSA((uint8_t *)&areaToSign.digest,
					   SHA1_DIGEST_SIZE,
					   &tSignature,
					   TPM_ALG_SHA1,
					   rsaPubKey);
	}
	if (rsaPubKey != NULL) {
	    RSA_free(rsaPubKey); 	/* @3 */
	}
    }
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
free(input);		/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("sign\n");
    printf("\n");
    printf("Runs TPM_Sign\n");
    printf("\n");
    printf("\t-hk signing key handle\n");
    printf("\t[-pwdk password for signing key (default zeros)]\n");
    printf("\t-if input area to hash and sign\n");
    printf("\t[-os sign signature file name (default do not save)]\n");
    printf("\t[-ik key file name to verify signature (default no verify)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


