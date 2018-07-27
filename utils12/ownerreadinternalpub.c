/********************************************************************************/
/*										*/
/*			    TPM 1.2 OwnerReadInternalPub			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ownerreadinternalpub.c 1286 2018-07-27 19:20:16Z kgoldman $	*/
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
    OwnerReadInternalPub_In	in;
    OwnerReadInternalPub_Out	out;
    const char			*keyHandleType = NULL;
    const char			*ownerPassword = NULL; 
    const char 			*pubkeyFilename = NULL;
    TPM_AUTHHANDLE 		sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		keyHandleType = argv[i];	
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
    if (keyHandleType == NULL) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (strcmp(keyHandleType, "ek") == 0) {
	in.keyHandle = TPM_RH_EK;
    }
    else if (strcmp(keyHandleType, "srk") == 0) {
	in.keyHandle = TPM_RH_SRK;
    }
    else {
	printf("Bad parameter parameter %s for -ha\n", keyHandleType);
	printUsage();
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
			 TPM_ORD_OwnerReadInternalPub,
			 sessionHandle0, ownerPassword, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);
	
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* save the TPM_PUBKEY key */
    if ((rc == 0) && (pubkeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.publicPortion,
				     (MarshalFunction_t)TSS_TPM_PUBKEY_Marshalu,
				     pubkeyFilename);
    }
    if (rc == 0) {
	if (verbose) TSS_PrintAll("public key",
				  out.publicPortion.pubKey.key,
				  out.publicPortion.pubKey.keyLength);
	if (verbose) printf("ownerreadinternalpub: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ownerreadinternalpub: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("ownerreadinternalpub\n");
    printf("\n");
    printf("Runs TPM_OwnerReadInternalPub\n");
    printf("\n");
    printf("\t-ha key handle type [ek, srk]\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-op TPM_PUBKEY key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


