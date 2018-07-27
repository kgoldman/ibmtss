/********************************************************************************/
/*										*/
/*			    TPM 1.2 CreateWrapKey				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: makeidentity.c 1158 2018-04-17 14:41:00Z kgoldman $		*/
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
    CreateWrapKey_In		in;
    CreateWrapKey_Out		out;
    TPM_KEY_HANDLE		parentHandle = TPM_RH_SRK;
    int 			signing = FALSE;
    int 			storage = FALSE;
    const char 			*usagePassword = NULL;
    const char 			*migrationPassword = NULL;
    const char 			*parentPassword = NULL;
    TPMT_HA 			usageHash;
    TPMT_HA 			migrationHash;
    const char 			*keyFilename = NULL;
    const char 			*pubkeyFilename = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i], "srk") == 0) {
		    parentHandle = TPM_RH_SRK;
		}
		else {
		    sscanf(argv[i],"%x", &parentHandle);
		}
	    }
	    else {
		printf("Missing parameter for -hp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-si") == 0) {
	    signing = TRUE;
	}
	else if (strcmp(argv[i],"-st") == 0) {
	    storage = TRUE;
	}
	else if (!strcmp("-pwdk",argv[i])) {
	    i++;
	    if (i < argc) {
		usagePassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdk\n");
		printUsage();
	    }
	}
	else if (!strcmp("-pwdm",argv[i])) {
	    i++;
	    if (i < argc) {
		migrationPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdm\n");
		printUsage();
	    }
	}
	else if (!strcmp("-pwdp",argv[i])) {
	    i++;
	    if (i < argc) {
		parentPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdp\n");
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
    /* must have exactly one set */
    if (signing == storage) {
	printf("One of -si -st must be set\n");
    }
    if (rc == 0) {
	if (usagePassword == NULL) {
	    memset(in.dataUsageAuth, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    usageHash.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&usageHash,
				   strlen(usagePassword), usagePassword,
				   0, NULL);
	    memcpy(in.dataUsageAuth, (uint8_t *)&usageHash.digest, SHA1_DIGEST_SIZE);
	}
    }
    if (rc == 0) {
	if (migrationPassword == NULL) {
	    memset(in.dataMigrationAuth, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    migrationHash.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&migrationHash,
				   strlen(migrationPassword), migrationPassword,
				   0, NULL);
	    memcpy(in.dataMigrationAuth, (uint8_t *)&migrationHash.digest, SHA1_DIGEST_SIZE);
	}
    }
    if (rc == 0) {
	in.parentHandle = parentHandle;
	/* storage key */
	if (storage) {
	    in.keyInfo.keyUsage = TPM_KEY_STORAGE;
	    in.keyInfo.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;  
	    in.keyInfo.algorithmParms.sigScheme = TPM_ES_NONE;  
	}
	/* signing key */
	else {
	    in.keyInfo.keyUsage = TPM_KEY_SIGNING;
	    in.keyInfo.algorithmParms.encScheme = TPM_ES_NONE;  
	    in.keyInfo.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;  
	}
	in.keyInfo.algorithmParms.algorithmID = TPM_ALG_RSA;  
	in.keyInfo.keyFlags = 0;
	if (usagePassword == NULL) {
	    in.keyInfo.authDataUsage = TPM_AUTH_NEVER;
	}
	else {
	    in.keyInfo.authDataUsage = TPM_AUTH_ALWAYS;
	}
	in.keyInfo.algorithmParms.parms.rsaParms.keyLength = 2048;  
	in.keyInfo.algorithmParms.parms.rsaParms.numPrimes = 2;  
	in.keyInfo.algorithmParms.parms.rsaParms.exponentSize = 0;  
	in.keyInfo.PCRInfo.localityAtCreation = TPM_LOC_ZERO;
	in.keyInfo.PCRInfo.localityAtRelease = TPM_LOC_ALL;
	in.keyInfo.PCRInfo.creationPCRSelection.sizeOfSelect = 3;
	memset(in.keyInfo.PCRInfo.creationPCRSelection.pcrSelect, 0, 3);
	in.keyInfo.PCRInfo.releasePCRSelection.sizeOfSelect = 3;
	memset(in.keyInfo.PCRInfo.releasePCRSelection.pcrSelect, 0, 3);
	memset(in.keyInfo.PCRInfo.digestAtCreation, 0, SHA1_DIGEST_SIZE);
	memset(in.keyInfo.PCRInfo.digestAtRelease, 0, SHA1_DIGEST_SIZE);
	in.keyInfo.pubKey.keyLength = 0;   
	in.keyInfo.encData.keyLength = 0;
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
			 TPM_ORD_CreateWrapKey,
			 sessionHandle0, parentPassword, sessionAttributes0,
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
	rc = TSS_File_WriteStructure(&out.wrappedKey,
				     (MarshalFunction_t)TSS_TPM_KEY12_Marshalu,
				     keyFilename);
    }
    /* save the TPM_PUBKEY key from the TPM_KEY12 idKey */
    if ((rc == 0) && (pubkeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.wrappedKey,
				     (MarshalFunction_t)TSS_TPM_KEY12_PUBKEY_Marshalu,
				     pubkeyFilename);
    }
    if (rc == 0) {
	if (verbose) printf("createwrapkey: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("createwrapkey: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createwrapkey\n");
    printf("\n");
    printf("Runs TPM_CreateWrapKey\n");
    printf("\n");
    printf("\t-st storage key\n");
    printf("\t-si signing key\n");
    printf("\t[-hp parent handle, can be srk (default srk)]\n");
    printf("\t[-pwdp password for parent key (default empty)]\n");
    printf("\t[-pwdk usage password for key (default zeros)]\n");
    printf("\t[-pwdm migration password for key (default zeros)]\n");
    printf("\t[-ok TPM_KEY12 key file name (default do not save)]\n");
    printf("\t[-op TPM_PUBKEY key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se0 OSAP session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


