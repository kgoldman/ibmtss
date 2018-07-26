/********************************************************************************/
/*										*/
/*			    Extend		 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: extend.c 1258 2018-06-28 16:46:10Z kgoldman $		*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Extend_In 			in;
    Extend_Out 			out;
    TPM_PCRINDEX 		pcrNum = IMPLEMENTATION_PCR;
    const char 			*dataString = NULL;
    const char 			*datafilename = NULL;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrNum);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		dataString = argv[i];
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
	    } else {
		printf("-if option needs a value\n");
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
    if (pcrNum >= IMPLEMENTATION_PCR) {
	printf("Missing or bad PCR handle parameter -ha\n");
	printUsage();
    }
    if ((dataString == NULL) && (datafilename == NULL)) {
	printf("Data string or data file must be specified\n");
	printUsage();
    }
    if ((dataString != NULL) && (datafilename != NULL)) {
	printf("Data string and data file cannot both be specified\n");
	printUsage();
    }
    if ((dataString != NULL) && (strlen(dataString) > SHA1_DIGEST_SIZE)) {
	printf("Data length greater than maximum hash size %u bytes\n", SHA1_DIGEST_SIZE);
	printUsage();
    }
    if (rc == 0) {
	in.pcrNum = pcrNum;
	/* append zero padding to maximum hash algorithm length */
	memset((uint8_t *)&in.inDigest, 0, SHA1_DIGEST_SIZE);
    }
    if (rc == 0) {
	if (dataString != NULL) {
	    if (verbose) printf("Extending %u bytes from stream\n",
				(unsigned int)strlen(dataString));
	    memcpy((uint8_t *)&in.inDigest, dataString, strlen(dataString));
	}
    }
    if (datafilename != NULL) {
	unsigned char 	*fileData = NULL;
	size_t 		length;
	if (rc == 0) {
	    rc = TSS_File_ReadBinaryFile(&fileData, &length, datafilename);
	}
	if (rc == 0) {
	    if (length > SHA1_DIGEST_SIZE) {
		printf("Data length greater than maximum hash size %u bytes\n", SHA1_DIGEST_SIZE);
		rc = EXIT_FAILURE;
	    } 
	}
	if (rc == 0) {
	    if (verbose) printf("Extending %u bytes from file\n", (unsigned int)length);
	    memcpy((uint8_t *)&in.inDigest, fileData, length);
	}
	free(fileData);
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
			 TPM_ORD_Extend,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) TSS_PrintAll("PCR", out.outDigest, SHA1_DIGEST_SIZE);
	if (verbose) printf("extend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("extend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("extend\n");
    printf("\n");
    printf("Runs TPM_Extend\n");
    printf("\n");
    printf("\t-ha PCR handle\n");
    printf("\t-ic data string, 0 pad appended to SHA-1 length\n");
    printf("\t-if data file, 0 pad appended to SHA-1 length\n");
    exit(1);	
}
