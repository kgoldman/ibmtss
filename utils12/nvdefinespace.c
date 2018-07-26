/********************************************************************************/
/*										*/
/*			    TPM 1.2 NV_DefineSpace				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nvdefinespace.c 1258 2018-06-28 16:46:10Z kgoldman $		*/
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
#include <ibmtss/Unmarshal12_fp.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_DefineSpace12_In		in;
    TPM12_NV_INDEX		nvIndex = 0;
    uint32_t 			dataSize = 0xffffffff;
    uint32_t 			permission = 0;
    const char			*ownerPassword = NULL; 
    const char			*nvPassword = NULL; 
    uint8_t			nvAuth[SHA1_DIGEST_SIZE];	/* either command line or zeros */
    TPMT_HA 			nvAuthHash;
    TPM_AUTHHANDLE 		sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sz") == 0) {
	    i++;
	    if (i < argc) {
		dataSize = atoi(argv[i]);
	    }
	    else {
		printf("-sz option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-per") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &permission);
	    }
	    else {
		printf("Missing parameter for -ha\n");
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
    if (nvIndex == 0) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (dataSize == 0xffffffff) {
	printf("Missing handle parameter -sz\n");
	printUsage();
    }
    if (rc == 0) {
	if (verbose) printf("nvdefinespace: index password %s\n", nvPassword);
	if (nvPassword == NULL) {
	    memset(nvAuth, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    nvAuthHash.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&nvAuthHash,
				   strlen(nvPassword), nvPassword,
				   0, NULL);
	    memcpy(nvAuth, (uint8_t *)&nvAuthHash.digest, SHA1_DIGEST_SIZE);
	}
 	if (verbose) TSS_PrintAll("Plaintext pwd", nvAuth, SHA1_DIGEST_SIZE);
   }
    if (rc == 0) {
	memcpy(in.encAuth, nvAuth, SHA1_DIGEST_SIZE);
	in.pubInfo.nvIndex = nvIndex;

	in.pubInfo.pcrInfoRead.pcrSelection.sizeOfSelect = 3;
	memset(in.pubInfo.pcrInfoRead.pcrSelection.pcrSelect, 0, 3);
	in.pubInfo.pcrInfoRead.localityAtRelease = TPM_LOC_ALL;
	memset(in.pubInfo.pcrInfoRead.digestAtRelease, 0, SHA1_DIGEST_SIZE);

	in.pubInfo.pcrInfoWrite.pcrSelection.sizeOfSelect = 3;
	memset(in.pubInfo.pcrInfoWrite.pcrSelection.pcrSelect, 0, 3);
	in.pubInfo.pcrInfoWrite.localityAtRelease = TPM_LOC_ALL;
	memset(in.pubInfo.pcrInfoWrite.digestAtRelease, 0, SHA1_DIGEST_SIZE);
	
	if (permission != 0) {	/* if permssion was specified on the command line */
	    in.pubInfo.permission.attributes = permission;
	}
	else if (nvPassword != NULL) {		/* if index auth */
	    in.pubInfo.permission.attributes = TPM_NV_PER_AUTHREAD | TPM_NV_PER_AUTHWRITE;
	}
	else {					/* if owner auth */
	    in.pubInfo.permission.attributes = TPM_NV_PER_OWNERREAD | TPM_NV_PER_OWNERWRITE;
	}
	in.pubInfo.bReadSTClear = 0;
	in.pubInfo.bWriteSTClear = 0;
	in.pubInfo.bWriteDefine = 0;
	in.pubInfo.dataSize = dataSize;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_NV_DefineSpace,
			 sessionHandle0, ownerPassword, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);
	
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("nvdefinespace: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvdefinespace: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvdefinespace\n");
    printf("\n");
    printf("Runs TPM_NV_DefineSpace\n");
    printf("\n");
    printf("\t-ha NV index handle\n");
    printf("\t\tffffffff sets NV lock\n");
    printf("\t-sz data size in decimal\n");
    printf("\t\tsize 0 undefines the index\n");
    printf("\t[-per permission: A hex number that defines the permission attributes]\n");
    printf("\t\tDefault 40004 TPM_NV_PER_AUTHREAD|TPM_NV_PER_AUTHWRITE if -pwdn is set\n");
    printf("\t\tDefault 20002 TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE if -pwdn is not set\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-pwdn password for NV index (default zeros)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}

