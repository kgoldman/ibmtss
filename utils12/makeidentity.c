/********************************************************************************/
/*										*/
/*			    TPM 1.2 Make Identity				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: makeidentity.c 1286 2018-07-27 19:20:16Z kgoldman $		*/
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
#include <ibmtss/tpmstructures12.h>
#include <ibmtss/tssmarshal12.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    MakeIdentity_In		in;
    MakeIdentity_Out		out;
    const char 			*ownerPassword = NULL;
    const char 			*srkPassword = NULL;  
    const char 			*keyPassword = NULL;
    const char 			*keyFilename = NULL;
    const char 			*pubkeyFilename = NULL;
    uint8_t			keyAuth[SHA1_DIGEST_SIZE];	/* either command line or zeros */
    TPMT_HA 			keyHash;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i], "-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-pwds") == 0) {
	    i++;
	    if (i < argc) {
		srkPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwds\n");
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
	else if (!strcmp("-ok",argv[i])) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    } else {
		printf("Missing parameter for -ok\n");
		printUsage();
	    }
	}
	else if (!strcmp("-op",argv[i])) {
	    i++;
	    if (i < argc) {
		pubkeyFilename = argv[i];
	    } else {
		printf("Missing parameter for -op\n");
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
    if (rc == 0) {
	if (keyPassword == NULL) {
	    memset(keyAuth, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    keyHash.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&keyHash,
				   strlen(keyPassword), keyPassword,
				   0, NULL);
	    memcpy(keyAuth, (uint8_t *)&keyHash.digest, SHA1_DIGEST_SIZE);
	}
    }
    if (rc == 0) {
	memcpy(in.identityAuth, keyAuth, SHA1_DIGEST_SIZE);
	memset(in.labelPrivCADigest, 0, SHA1_DIGEST_SIZE);
	in.idKeyParams.keyUsage = TPM_KEY_IDENTITY; 
	in.idKeyParams.keyFlags = 0;
	if (keyPassword == NULL) {
	    in.idKeyParams.authDataUsage = TPM_AUTH_NEVER;
	}
	else {
	    in.idKeyParams.authDataUsage = TPM_AUTH_ALWAYS;
	}
	in.idKeyParams.algorithmParms.algorithmID = TPM_ALG_RSA;  
	in.idKeyParams.algorithmParms.encScheme = TPM_ES_NONE;  
	in.idKeyParams.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;  
	in.idKeyParams.algorithmParms.parms.rsaParms.keyLength = 2048;  
	in.idKeyParams.algorithmParms.parms.rsaParms.numPrimes = 2;  
	in.idKeyParams.algorithmParms.parms.rsaParms.exponentSize = 0;  
	in.idKeyParams.PCRInfo.localityAtCreation = TPM_LOC_ZERO;
	in.idKeyParams.PCRInfo.localityAtRelease = TPM_LOC_ALL;
	in.idKeyParams.PCRInfo.creationPCRSelection.sizeOfSelect = 0; 
	/* in.idKeyParams.PCRInfo.creationPCRSelection;  */
	in.idKeyParams.PCRInfo.releasePCRSelection.sizeOfSelect = 0;
	/* in.idKeyParams.PCRInfo.releasePCRSelection; */
	/* in.idKeyParams.PCRInfo.digestAtCreation;  */
	/* in.idKeyParams.PCRInfo.digestAtRelease; */
	in.idKeyParams.pubKey.keyLength = 0;   
	in.idKeyParams.encData.keyLength = 0;
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
			 TPM_ORD_MakeIdentity,
			 sessionHandle0, srkPassword, sessionAttributes0,
			 sessionHandle1, ownerPassword, sessionAttributes1,
			 TPM_RH_NULL, NULL, 0);
	
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* save the TPM_KEY12 key */
    if ((rc == 0) && (keyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.idKey,
				     (MarshalFunction_t)TSS_TPM_KEY12_Marshalu,
				     keyFilename);
    }
    /* save the TPM_PUBKEY key from the TPM_KEY12 idKey */
    if ((rc == 0) && (pubkeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.idKey,
				     (MarshalFunction_t)TSS_TPM_KEY12_PUBKEY_Marshalu,
				     pubkeyFilename);
    }
    if (rc == 0) {
	if (verbose) printf("makeidentity: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("makeidentity: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("makeidentity\n");
    printf("\n");
    printf("Runs TPM_MakeIdentity\n");
    printf("\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-pwds SRK password (default zeros)]\n");
    printf("\t[-pwdk password for key (default zeros)]\n");
    printf("\t[-ok TPM_KEY12 key file name (default do not save)]\n");
    printf("\t[-op TPM_PUBKEY key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se0 srk session handle / attributes\n");
    printf("\t-se1 owner session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


