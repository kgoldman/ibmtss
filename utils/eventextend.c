/********************************************************************************/
/*										*/
/*		      Extend an EVENT measurement file into PCRs		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: eventextend.c 1072 2017-09-11 19:55:31Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017.					*/
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

/* eventextend is test/demo code.  It parses a TPM2 event log file and extends the measurements
   into TPM PCRs.  This simulates the actions that would be performed by BIOS / firmware in a
   hardware platform.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>

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
    TCG_PCR_EVENT2 		event2;			/* TPM 2.0 event log entry */
    TCG_PCR_EVENT 		event;			/* TPM 1.2 event log entry */
    TCG_EfiSpecIDEvent 		specIdEvent;
    unsigned int 		lineNum;
    int 			endOfFile = FALSE;
    int				nospec = FALSE;
    PCR_Extend_In 		in;
	
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
	else if (strcmp(argv[i],"-nospec") == 0) {
	    nospec = TRUE;
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
    /*
    ** read the event log file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /* the first event is a TPM 1.2 format event */
    /* read an event line */
    if ((rc == 0) && !nospec) {
	rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
    }
    /* debug tracing */
    if (verbose && !endOfFile && (rc == 0) && !nospec) {
	printf("\neventextend: line 0\n");
	TSS_EVENT_Line_Trace(&event);
    }
    /* parse the event */
    if (verbose && !endOfFile && (rc == 0) && !nospec) {
	rc = TSS_SpecIdEvent_Unmarshal(&specIdEvent,
				       event.eventDataSize, event.event);
    }
    /* trace the event */
    if (verbose && !endOfFile && (rc == 0) && !nospec) {
	TSS_SpecIdEvent_Trace(&specIdEvent);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* scan each measurement 'line' in the binary */
    for (lineNum = 1 ; !endOfFile && (rc == 0) ; lineNum++) {
	/* read a TPM 2.0 hash agile event line */
	if (rc == 0) {
	    rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
	}
	/* debug tracing */
	if (verbose && !endOfFile && (rc == 0)) {
	    printf("\neventextend: line %u\n", lineNum);
	    TSS_EVENT2_Line_Trace(&event2);
	}
	/* don't extend no action events */
	if (!endOfFile && (rc == 0)) {
	    if (event2.eventType == EV_NO_ACTION) {
		continue;
	    }
	}
	if (!endOfFile && (rc == 0)) {
	    in.pcrHandle = event2.pcrIndex;
	    in.digests = event2.digests;
	    rc = TSS_Execute(tssContext,
			     NULL, 
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_PCR_Extend,
			     TPM_RS_PW, NULL, 0,
			     TPM_RH_NULL, NULL, 0);
	}
	/* for debug, read back and trace the PCR value after the extend */
	if (verbose) {
	    PCR_Read_In 		pcrReadIn;
	    PCR_Read_Out 		pcrReadOut;
	    if (!endOfFile && (rc == 0)) {
		pcrReadIn.pcrSelectionIn.count = 1;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].hash =
		    event2.digests.digests[0].hashAlg;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[event2.pcrIndex / 8] =
		    1 << (event2.pcrIndex % 8);
	    }
	    if (!endOfFile && (rc == 0)) {
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&pcrReadOut,
				 (COMMAND_PARAMETERS *)&pcrReadIn,
				 NULL,
				 TPM_CC_PCR_Read,
				 TPM_RH_NULL, NULL, 0);
 	    }
	    if (!endOfFile && (rc == 0)) {
		TSS_PrintAll("PCR digest",
			     pcrReadOut.pcrValues.digests[0].t.buffer,
			     pcrReadOut.pcrValues.digests[0].t.size);
	    }
	}
    }	
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
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
    printf("Extends a measurement file (binary) into TPM PCRs\n");
    printf("\n");
    printf("   Where the arguments are...\n");
    printf("    -if <input file> is the file containing the data to be extended\n");
    printf("    [-nospec file does not contain spec ID header (useful for incremental test)]\n");
    printf("\n");
    exit(-1);
}

