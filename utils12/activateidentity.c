/********************************************************************************/
/*										*/
/*			    TPM 1.2 ActivateIdentity				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: activateidentity.c 1294 2018-08-09 19:08:34Z kgoldman $	*/
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
    ActivateIdentity_In		in;
    ActivateIdentity_Out	out;
    TPM_KEY_HANDLE 		idKeyHandle;
    const char 			*ownerPassword = NULL;
    const char 			*ownerPasswordFilename = NULL;
    unsigned char 		*ownerPasswordData = NULL;
    const char 			*keyPassword = NULL;
    const char 			*keyFilename = NULL;
    const uint8_t		*ownerAuth;			/* either command line or file */
    const char 			*blobFilename = NULL;
    uint8_t			*blob = NULL;
    size_t 			blobSize;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    size_t 			length;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &idKeyHandle);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerPasswordFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
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
	else if (!strcmp("-ib",argv[i])) {
	    i++;
	    if (i < argc) {
		blobFilename = argv[i];
	    } else {
		printf("Missing parameter for -ib\n");
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
    if ((ownerPassword == NULL) && (ownerPasswordFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	printUsage();
    }
    if ((ownerPassword != NULL) && (ownerPasswordFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	printUsage();
    }
    if (blobFilename == NULL) {
	printf("\nMissing -ib argument\n");
	printUsage();
    }
    /* get the owner password from a file */
    if (ownerPasswordFilename != NULL) {
	if (rc == 0) {
	    rc = TSS_File_ReadBinaryFile(&ownerPasswordData,     /* freed @1 */
					 &length,
					 ownerPasswordFilename);
	}
	ownerAuth = ownerPasswordData;
    }
    else {
	ownerAuth = (uint8_t *)ownerPassword; 	/* can be NULL */
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&blob,     	/* freed @1 */
				     &blobSize,
				     blobFilename);
    }
    if (rc == 0) {
	if (blobSize > sizeof(in.blob)) {
	    printf("activateidentity: blob size %u greater than %u\n",
		   (unsigned int)blobSize, (unsigned int)sizeof(in.blob));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	in.idKeyHandle = idKeyHandle;
	in.blobSize = blobSize;
	memcpy(in.blob, blob, blobSize);
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
			 TPM_ORD_ActivateIdentity,
			 sessionHandle0, keyPassword, sessionAttributes0,
			 sessionHandle1, ownerAuth, sessionAttributes1,
			 TPM_RH_NULL, NULL, 0);
	
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* save the key */
    if ((rc == 0) && (keyFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile((const unsigned char *)&out.symmetricKey.data,
				      out.symmetricKey.size,
				      keyFilename);
    }
    if (rc == 0) {
	if (verbose) printf("activateidentity: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("activateidentity: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(blob);	/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("activateidentity\n");
    printf("\n");
    printf("Runs TPM_ActivateIdentity\n");
    printf("\n");
    printf("\t-ha ID key handle\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-pwdof owner authorization file name\n");
    printf("\t[-pwdk password for key (default zeros)]\n");
    printf("\t-ib encrypted blob file name\n");
    printf("\t[-ok symmetric key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se0 srk session handle / attributes\n");
    printf("\t-se1 owner session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}


