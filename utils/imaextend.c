/********************************************************************************/
/*										*/
/*		      Extend an IMA measurement list into PCR 10		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: imaextend.c 978 2017-04-04 15:37:15Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2014, 2017.					*/
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

/* imaextend is test/demo code.  It parses a TPM2 event log file and extends the measurements
   into TPM PCRs.  This simulates the actions that would be performed by BIOS / firmware in a
   hardware platform.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>

#include "imalib.h"

/* local prototypes */

static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      TPMI_DH_PCR pcrHandle);
static void printUsage(void);

int verbose = FALSE;
int vverbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 		rc = 0;
    int 		i = 0;
    TSS_CONTEXT		*tssContext = NULL;
    PCR_Extend_In 	in;
    const char 		*infilename = NULL;
    FILE 		*infile = NULL;
    int 		littleEndian = FALSE;
	
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		infilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
		exit(2);
	    }
	}
	else if (strcmp(argv[i],"-le") == 0) {
	    littleEndian = TRUE; 
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    vverbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (infilename == NULL) {
	printf("Missing -if argument\n");
	printUsage();
    }
    /*
    ** read the IMA event log file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    unsigned char zeroDigest[SHA1_DIGEST_SIZE];
    unsigned char oneDigest[SHA1_DIGEST_SIZE];
    if (rc == 0) {
	uint32_t algs;				/* hash algorithm iterator */
	memset(zeroDigest, 0, SHA1_DIGEST_SIZE);
	memset(oneDigest, 0xff, SHA1_DIGEST_SIZE);
	in.digests.count = 2;			/* extend SHA-1 and SHA-256 banks */
	in.digests.digests[0].hashAlg = TPM_ALG_SHA1;
	in.digests.digests[1].hashAlg = TPM_ALG_SHA256;
	/* IMA zero extends into the SHA-256 bank */
	for (algs = 0 ; algs < in.digests.count ; algs++) {
	    memset((uint8_t *)&in.digests.digests[algs].digest, 0, sizeof(TPMU_HA));
	}
    }
    if ((rc == 0) && verbose) {
	printf("Initial PCR 10 value\n");
	rc = pcrread(tssContext, 10);
    }
    ImaEvent imaEvent;
    unsigned int lineNum;
    int endOfFile = FALSE;
    /* scan each measurement 'line' in the binary */
    for (lineNum = 0 ; !endOfFile && (rc == 0) ; lineNum++) {
	/* read an IMA event line */
	IMA_Event_Init(&imaEvent);
	if (rc == 0) {
	    rc = IMA_Event_ReadFile(&imaEvent, &endOfFile, infile,
				    littleEndian);
	}
	if (rc == 0) {
	    in.pcrHandle = imaEvent.pcrIndex;		/* normally PCR 10 */
	}
	/* debug tracing */
	if (verbose && !endOfFile && (rc == 0)) {
	    printf("\nimaextend: line %u\n", lineNum);
	    IMA_Event_Trace(&imaEvent, FALSE);
	}
	/* copy the SHA-1 digest to be extended */
	if ((rc == 0) && !endOfFile) {
	    int notAllZero = memcmp(imaEvent.digest, zeroDigest, SHA1_DIGEST_SIZE);
	    /* IMA has a quirk where some measurements store a zero digest in the event log, but
	       extend ones into PCR 10 */
	    if (notAllZero) {
		memcpy((uint8_t *)&in.digests.digests[0].digest, imaEvent.digest, SHA1_DIGEST_SIZE);
		memcpy((uint8_t *)&in.digests.digests[1].digest, imaEvent.digest, SHA1_DIGEST_SIZE);
	    }
	    else {
		memset((uint8_t *)&in.digests.digests[0].digest, 0xff, SHA1_DIGEST_SIZE);
		memset((uint8_t *)&in.digests.digests[1].digest, 0xff, SHA1_DIGEST_SIZE);
	    }
	}	
	if ((rc == 0) && !endOfFile) {
	    rc = TSS_Execute(tssContext,
			     NULL, 
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_PCR_Extend,
			     TPM_RS_PW, NULL, 0,
			     TPM_RH_NULL, NULL, 0);
	}
	if ((rc == 0) && !endOfFile && verbose) {
	    rc = pcrread(tssContext, imaEvent.pcrIndex);
	}
	IMA_Event_Free(&imaEvent);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("imaextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("imaextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}

static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      TPMI_DH_PCR pcrHandle)
{
    TPM_RC 		rc = 0;
    /* for debug, read back and trace the PCR value after the extend */
    PCR_Read_In 		pcrReadIn;
    PCR_Read_Out 		pcrReadOut;

    if (rc == 0) {
	pcrReadIn.pcrSelectionIn.count = 2;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA1;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].hash = TPM_ALG_SHA256;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].sizeofSelect = 3;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[0] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[1] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[2] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[pcrHandle / 8] =
	    1 << (pcrHandle % 8);
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[pcrHandle / 8] =
	    1 << (pcrHandle % 8);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&pcrReadOut,
			 (COMMAND_PARAMETERS *)&pcrReadIn,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	TSS_PrintAll("PCR digest SHA-1",
		     pcrReadOut.pcrValues.digests[0].t.buffer,
		     pcrReadOut.pcrValues.digests[0].t.size);
	TSS_PrintAll("PCR digest SHA-256",
		     pcrReadOut.pcrValues.digests[1].t.buffer,
		     pcrReadOut.pcrValues.digests[1].t.size);
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("imaextend\n");
    printf("\n");
    printf("Runs TPM2_PCR_Extend to Extends a SHA-1 IMA measurement file (binary) into TPM PCRs\n");
    printf("The IMA measurement is directly extended into the SHA-1 bank, and a zero padded\n");
    printf("measurement is extended into the SHA-256 bank\n");
    printf("This handles the case where a zero measurement extends ones into the IMA PCR\n");
    printf("\n");
    printf("\t-if IMA event log file name\n");
    printf("\t[-le input file is little endian (default big endian)\n]");
    printf("\n");
    exit(1);
}

