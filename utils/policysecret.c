/********************************************************************************/
/*										*/
/*			    PolicySecret	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2022.					*/
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
#include <ibmtss/tssmarshal.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    PolicySecret_In 		in;
    PolicySecret_Out 		out;
    TPMI_DH_ENTITY		authHandle = 0;
    TPMI_SH_POLICY		policySession = 0;
    const char 			*nonceTPMFilename = NULL;
    const char 			*cpHashAFilename = NULL;
    const char			*policyRefFilename = NULL;
    int32_t			expiration = 0;
    const char			*ticketFilename = NULL;
    const char			*timeoutFilename = NULL;
    const char			*entityPassword = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */

    in.nonceTPM.b.size = 0;
    in.cpHashA.b.size = 0;
    in.policyRef.b.size = 0;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &authHandle);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hs") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &policySession);
	    }
	    else {
		printf("Missing parameter for -hs\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-in") == 0) {
	    i++;
	    if (i < argc) {
		nonceTPMFilename = argv[i];
	    }
	    else {
		printf("-in option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cp") == 0) {
	    i++;
	    if (i < argc) {
		cpHashAFilename = argv[i];
	    }
	    else {
		printf("-cp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pref") == 0) {
	    i++;
	    if (i < argc) {
		policyRefFilename = argv[i];
	    }
	    else {
		printf("-pref option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-exp") == 0) {
	    i++;
	    if (i < argc) {
		expiration = atoi(argv[i]);
	    }
	    else {
		printf("Missing parameter for -exp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwde") == 0) {
	    i++;
	    if (i < argc) {
		entityPassword = argv[i];
	    }
	    else {
		printf("-pwda option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-tk") == 0) {
	    i++;
	    if (i < argc) {
		ticketFilename = argv[i];
	    }
	    else {
		printf("-tk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-to") == 0) {
	    i++;
	    if (i < argc) {
		timeoutFilename = argv[i];
	    }
	    else {
		printf("-to option needs a value\n");
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
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (authHandle == 0) {
	printf("Missing authorizing entity handle parameter -ha\n");
	printUsage();
    }
    if (policySession == 0) {
	printf("Missing policy session handle parameter -hs\n");
	printUsage();
    }
    if (rc == 0) {
	in.authHandle = authHandle;
	in.policySession = policySession;
    }
    if ((rc == 0) && (nonceTPMFilename != NULL)) {
	rc = TSS_File_Read2B(&in.nonceTPM.b,
			     sizeof(in.nonceTPM.t.buffer),
			     nonceTPMFilename);
    }
    if ((rc == 0) && (cpHashAFilename != NULL)) {
	rc = TSS_File_Read2B(&in.cpHashA.b,
			     sizeof(in.cpHashA.t.buffer),
			     cpHashAFilename);
    }
    if ((rc == 0) && (policyRefFilename != NULL)) {
	rc = TSS_File_Read2B(&in.policyRef.b,
			     sizeof(in.policyRef.t.buffer),
			     policyRefFilename);
    }
    if (rc == 0) {
	in.expiration = expiration;
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
			 TPM_CC_PolicySecret,
			 sessionHandle0, entityPassword, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (ticketFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.policyTicket,
				     (MarshalFunction_t)TSS_TPMT_TK_AUTH_Marshalu,
				     ticketFilename);
    }
    if ((rc == 0) && (timeoutFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.timeout.b.buffer,
				      out.timeout.b.size,
				      timeoutFilename); 
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("policysecret: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("policysecret: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("policysecret\n");
    printf("\n");
    printf("Runs TPM2_PolicySecret\n");
    printf("\n");
    printf("\t-ha\tauthorizing entity handle\n");
    printf("\t-hs\tpolicy session handle\n");
    printf("\t[-in\tnonceTPM file (default none)]\n");
    printf("\t[-cp\tcpHash file (default none)]\n");
    printf("\t[-pref\tpolicyRef file (default none)]\n");
    printf("\t[-exp\texpiration (default none)]\n");
    printf("\t[-pwde\tauthorizing entity password (default empty)]\n");
    printf("\t[-tk\tticket file name]\n");
    printf("\t[-to\ttimeout file name]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
