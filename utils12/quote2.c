/********************************************************************************/
/*										*/
/*			    TPM 1.2 Quote2					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: quote2.c 1286 2018-07-27 19:20:16Z kgoldman $		*/
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
    Quote2_In			in;
    Quote2_Out			out;
    TPM_KEY_HANDLE		keyHandle = 0;
    const char			*keyPassword = NULL; 
    const char			*signatureFilename = NULL;
    const char			*externalDataFilename = NULL;
    unsigned char 		*externalData = NULL;
    size_t 			externalDatalength;
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
	else if (strcmp(argv[i],"-ed") == 0) {
	    i++;
	    if (i < argc) {
		externalDataFilename = argv[i];
	    }
	    else {
		printf("-ed option needs a value\n");
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
    if (rc == 0) {
	if (externalDataFilename != NULL) {
	    if (rc == 0) {
		rc = TSS_File_ReadBinaryFile(&externalData ,     /* freed @1*/
					     &externalDatalength,
					     externalDataFilename);
	    }
	    if (rc == 0) {
		if (externalDatalength != TPM_NONCE_SIZE) {
		    printf("externalData %s must contain %u bytes, is %u\n",
			   externalDataFilename, TPM_NONCE_SIZE,
			   (unsigned int)externalDatalength);
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
	    }
	    if (rc == 0) {
		memcpy(in.externalData, externalData, TPM_NONCE_SIZE);
	    }
	}
	else {
	    memset(in.externalData, 0, TPM_NONCE_SIZE);
	}
    }
    if (rc == 0) {
	in.keyHandle = keyHandle;
	in.targetPCR.sizeOfSelect = 3;
	in.targetPCR.pcrSelect[0] = 0;
	in.targetPCR.pcrSelect[1] = 0;
	in.targetPCR.pcrSelect[2] = 0;
	in.addVersion = 1;
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
			 TPM_ORD_Quote2,
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
	TPM_QUOTE_INFO2 q1;
	uint8_t		*q1Buffer = NULL;		/* freed @1 */
	uint16_t	q1Written;
	uint8_t		*vBuffer = NULL;		/* freed @2 */
	uint16_t	vWritten;
	TPMT_HA		q1Digest;
	TPM_KEY12 	quoteKey;
	RSA         	*rsaPubKey = NULL;
	TPMT_SIGNATURE 	tSignature;

	/* construct marshaled TPM_QUOTE_INFO2 */
	if (rc == 0) {
	    memcpy(&q1.fixed, "QUT2", 4);
	    memcpy(&(q1.externalData), &in.externalData, TPM_NONCE_SIZE);
	    q1.infoShort = out.pcrData;
	    rc = TSS_Structure_Marshal(&q1Buffer,	/* freed @1 */
				       &q1Written,
				       &q1,
				       (MarshalFunction_t)TSS_TPM_QUOTE_INFO2_Marshalu);
	}
	/* construct marshaled TPM_CAP_VERSION_INFO */
	if (rc == 0) {
	    rc = TSS_Structure_Marshal(&vBuffer,	/* freed @2 */
				       &vWritten,
				       &out.versionInfo,
				       (MarshalFunction_t)TSS_TPM_CAP_VERSION_INFO_Marshalu);
	}
	/* recalculate the signed hash */
	if (rc == 0) {
	    q1Digest.hashAlg = TPM_ALG_SHA1;
	    rc = TSS_Hash_Generate(&q1Digest,	
				   q1Written, q1Buffer,	/* TPM_QUOTE_INFO2 */
				   vWritten, vBuffer,	/* TPM_CAP_VERSION_INFO */
				   0, NULL);
	}
	/* get the signing (quote public) key */
	if (rc == 0) {
	    rc = TSS_File_ReadStructure(&quoteKey,
					(UnmarshalFunction_t)TSS_TPM_KEY12_Unmarshalu,
					keyFilename);
	}
	/* construct the OpenSSL RSA public key token */
	if (rc == 0) {
	    unsigned char earr[3] = {0x01, 0x00, 0x01};
	    rc = TSS_RSAGeneratePublicToken
		 (&rsaPubKey,			/* freed @3 */
		  quoteKey.pubKey.key,	 	/* public modulus */
		  quoteKey.pubKey.keyLength,
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
	    rc = verifyRSASignatureFromRSA((uint8_t *)&q1Digest.digest,
					   SHA1_DIGEST_SIZE,
					   &tSignature,
					   TPM_ALG_SHA1,
					   rsaPubKey);
	}
	free(q1Buffer);		/* @1 */
	free(vBuffer);		/* @2 */
	if (rsaPubKey != NULL) {
	    RSA_free(rsaPubKey); 	/* @3 */
	}
    }
    if (rc == 0) {
	if (verbose) printf("quote2: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("quote2: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(externalData);
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("quote2\n");
    printf("\n");
    printf("Runs TPM_Quote2\n");
    printf("\n");
    printf("\t-hk quoting key handle\n");
    printf("\t[-pwdk password for quoting key (default zeros)]\n");
    printf("\t[-ed external data file name (default zeros)]\n");
    printf("\t[-os quote signature file name (default do not save)]\n");
    printf("\t[-ik key file name for verify (default do not verify)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


