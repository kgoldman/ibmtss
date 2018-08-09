/********************************************************************************/
/*										*/
/*			    TPM 1.2 NV_WriteValue				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nvwritevalue.c 1294 2018-08-09 19:08:34Z kgoldman $		*/
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
    NV_WriteValue_In		in;
    TPM12_NV_INDEX		nvIndex = 0xfffffffe;
    const char			*ownerPassword = NULL; 
    unsigned int		dataSource = 0;
    const char 			*commandData = NULL;
    const char 			*datafilename = NULL;
    uint16_t 			offset = 0;			/* default 0 */
    size_t 			writeLength;		/* file bytes to write */
    unsigned char 		*writeBuffer = NULL; 	/* file buffer to write */
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
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		commandData = argv[i];
		dataSource++;
	    }
	    else {
		printf("-ic option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-if")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
		dataSource++;
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-off") == 0) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
	    }
	    else {
		printf("-off option needs a value\n");
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
    if (nvIndex == 0xfffffffe) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (dataSource > 1) {
	printf("More than one input data source (-if, -ic)\n");
	printUsage();
    }
    /* if there is no input data source, default to 0 byte write */
    if ((rc == 0) && (dataSource == 0)) {
	in.dataSize = 0;
    }
    /* -if, file data can be written in chunks */
    if ((rc == 0) && (datafilename != NULL)) {
	rc = TSS_File_ReadBinaryFile(&writeBuffer,     /* freed @1 */
				     &writeLength,
				     datafilename);
    }
    if ((rc == 0) && (datafilename != NULL)) {
	if (writeLength > sizeof(in.data)) {
	    printf("nvwritevalue: size %u greater than %u\n",
		   (unsigned int)writeLength, (unsigned int)sizeof(in.data));	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    in.dataSize = writeLength;
	    memcpy(in.data, writeBuffer, writeLength);
	}
    }
    if ((rc == 0) && (commandData != NULL)) {
	if (strlen(commandData) >  sizeof(in.data)) {
	    printf("nvwritevalue: size %u greater than %u\n",
		   (unsigned int)strlen(commandData), (unsigned int)sizeof(in.data));	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    in.dataSize = strlen(commandData);
	    memcpy(in.data, commandData, strlen(commandData));
	}
    }
    if (rc == 0) {
       in.nvIndex = nvIndex;
       in.offset = offset;
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
			 TPM_ORD_NV_WriteValue,
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
	if (verbose) printf("nvwritevalue: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvwritevalue: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(writeBuffer);	/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvwritevalue\n");
    printf("\n");
    printf("Runs TPM_NV_WriteValue\n");
    printf("\n");
    printf("\t-ha NV index handle\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-ic data string]\n");
    printf("\t[-if data file]\n");
    printf("\t[-off offset (default 0)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}

