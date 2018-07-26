/********************************************************************************/
/*										*/
/*		      Extend a TPM 1.2 EVENT measurement file into PCRs		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: eventextend.c 1258 2018-06-28 16:46:10Z kgoldman $		*/
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

/* eventextend is test/demo code.  It parses a TPM2 event log file and extends the measurements into
   TPM PCRs or simulated PCRs.  This simulates the actions that would be performed by BIOS /
   firmware in a hardware platform.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>

#include "eventlib.h"

/* local prototypes */

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int 			i = 0;
    TSS_CONTEXT			*tssContext = NULL;
    const char 			*infilename = NULL;
    FILE 			*infile = NULL;
    int				tpm = FALSE;	/* extend into TPM */
    int				sim = FALSE;	/* extend into simulated PCRs */
    int				noSpace = FALSE;
    int 			pcrNum = 0;	/* PCR number iterator */
    TPM_PCRINDEX 		pcrMax = 7;
    TPMT_HA 			simPcrs[IMPLEMENTATION_PCR];
    TPMT_HA 			bootAggregate;
    TCG_PCR_EVENT 		event;			/* TPM 1.2 event log entry */
    unsigned int 		lineNum;
    int 			endOfFile = FALSE;
	
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
	else if (strcmp(argv[i],"-tpm") == 0) {
	    tpm = TRUE;
	}
	else if (strcmp(argv[i],"-sim") == 0) {
	    sim = TRUE;
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
	}
	else if (strcmp(argv[i],"-pcrmax") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrMax);
	    }
	    else {
		printf("Missing parameter for -pcrmax");
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
    if (infilename == NULL) {
	printf("Missing -if argument\n");
	printUsage();
    }
    if (!tpm && !sim) {
	printf("-tpm or -sim must be specified\n");
	printUsage();
    }
    /*
    ** read the event log file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /* Start a TSS context */
    if ((rc == 0) && tpm) {
	rc = TSS_Create(&tssContext);
    }
    /* simulated BIOS PCRs start at zero at boot */
    if ((rc == 0) && sim) {
	bootAggregate.hashAlg = TPM_ALG_SHA1;
	for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	    /* initialize each algorithm ID  */
	    simPcrs[pcrNum].hashAlg = TPM_ALG_SHA1;
	    memset(&simPcrs[pcrNum].digest.sha1, 0, SHA1_DIGEST_SIZE);
	}
    }
    /* scan each measurement 'line' in the binary */
    for (lineNum = 0 ; (rc == 0) && !endOfFile ; lineNum++) {

	/* read a TPM 2.0 hash agile event line */
	if (rc == 0) {
	    rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
	}
	/* debug tracing */
	if ((rc == 0) && !endOfFile && verbose) {
	    printf("\neventextend: line %u\n", lineNum);
	    TSS_EVENT_Line_Trace(&event);
	}
	/* don't extend no action events */
	if ((rc == 0) && !endOfFile) {
	    if (event.eventType == EV_NO_ACTION) {
		continue;
	    }
	}
	if ((rc == 0) && !endOfFile && tpm) {	/* extend TPM */
	    Extend_In 			in;
	    Extend_Out 			out;

	    if (rc == 0) {
		in.pcrNum = event.pcrIndex;
		memcpy(in.inDigest, event.digest, SHA1_DIGEST_SIZE);
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&out, 
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_ORD_Extend,
				 TPM_RH_NULL, NULL, 0);
	    }
	    if ((rc == 0) && verbose) {
		TSS_PrintAll("PCR digest", out.outDigest, SHA1_DIGEST_SIZE);
	    }
	}
	if ((rc == 0) && !endOfFile && sim) {	/* extend simulated PCRs */
	    rc = TSS_EVENT_PCR_Extend(simPcrs, &event);
	}
    }
    {
	if (tpm) {
	    TPM_RC rc1 = TSS_Delete(tssContext);
	    if (rc == 0) {
		rc = rc1;
	    }
	}
    }
    if ((rc == 0) && sim) {
	/* trace the virtual PCRs */
	if (rc == 0) {
	    char pcrString[9];	/* PCR number */

	    printf("\n");
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		sprintf(pcrString, "PCR %02u:", pcrNum);
		if (!noSpace) {
		    /* TSS_PrintAllLogLevel() with a log level of LOGLEVEL_INFO to print the byte
		       array on one line with no length */
		    TSS_PrintAllLogLevel(LOGLEVEL_INFO, pcrString, 1,
					 simPcrs[pcrNum].digest.sha1, SHA1_DIGEST_SIZE);
		}
		else {	/* print with no spaces */
		    uint32_t bp;
		    printf("PCR %02u: ", pcrNum);
		    for (bp = 0 ; bp < SHA1_DIGEST_SIZE ; bp++) {
			printf("%02x", simPcrs[pcrNum].digest.sha1[bp]);
		    }
		    printf("\n");
		}
	    }
	}
	/* calculate the boot aggregate, hash of PCR 0-7 */
	if (rc == 0) {
	    int length[IMPLEMENTATION_PCR];
	    size_t j;
	    for (j = 0 ; j < IMPLEMENTATION_PCR ; j++) {
		if (j <= pcrMax) {	/* include PCRs up to here */
		    length[j] = SHA1_DIGEST_SIZE;
		}
		else {
		    length[j] = 0;	/* exclude PCRs after to here */
		}
	    }
	    rc = TSS_Hash_Generate(&bootAggregate,
				   length[0], &simPcrs[0].digest.sha1,
				   length[1], &simPcrs[1].digest.sha1,
				   length[2], &simPcrs[2].digest.sha1,
				   length[3], &simPcrs[3].digest.sha1,
				   length[4], &simPcrs[4].digest.sha1,
				   length[5], &simPcrs[5].digest.sha1,
				   length[6], &simPcrs[6].digest.sha1,
				   length[7], &simPcrs[7].digest.sha1,
				   length[8], &simPcrs[8].digest.sha1,
				   length[9], &simPcrs[9].digest.sha1,
				   length[10], &simPcrs[10].digest.sha1,
				   length[11], &simPcrs[11].digest.sha1,
				   length[12], &simPcrs[12].digest.sha1,
				   length[13], &simPcrs[13].digest.sha1,
				   length[14], &simPcrs[14].digest.sha1,
				   length[15], &simPcrs[15].digest.sha1,
				   length[16], &simPcrs[16].digest.sha1,
				   length[17], &simPcrs[17].digest.sha1,
				   length[18], &simPcrs[18].digest.sha1,
				   length[19], &simPcrs[19].digest.sha1,
				   length[20], &simPcrs[20].digest.sha1,
				   length[21], &simPcrs[21].digest.sha1,
				   length[22], &simPcrs[22].digest.sha1,
				   length[23], &simPcrs[23].digest.sha1,
				   0, NULL);
	}
	/* trace the boot aggregate */
	if (rc == 0) {
	    if (!noSpace) {
		TSS_PrintAllLogLevel(LOGLEVEL_INFO, "\nboot aggregate:", 1,
				     bootAggregate.digest.sha1, SHA1_DIGEST_SIZE);
	    }
	    else {	/* print with no spaces */
		uint32_t bp;
		printf("\nboot aggregate: ");
		for (bp = 0 ; bp < SHA1_DIGEST_SIZE ; bp++) {
		    printf("%02x", bootAggregate.digest.sha1[bp]);
		}
		printf("\n");
	    }
	}
    }
    if (rc == 0) {
	if (verbose) printf("eventextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eventextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}

static void printUsage(void)
{
    printf("Usage: eventextend -if <measurement file> [-v]\n");
    printf("\n");
    printf("Extends a measurement file (binary) into a TPM or simulated PCRs\n");
    printf("\n");
    printf("\t-if <input file> is the file containing the data to be extended\n");
    printf("\t[-tpm extend TPM PCRs]\n");
    printf("\t[-sim calculate simulated PCRs and boot aggregate]\n");
    printf("\t[-pcrmax, with -sim, sets the highest PCR number to be used to calculate the\n"
	   "\t\tboot aggregate (default 7)]\n");
    printf("\t[-ns no space, no text, no newlines]\n");
    printf("\n");
    exit(-1);
}

