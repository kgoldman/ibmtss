/********************************************************************************/
/*										*/
/*			    ObjectChangeAuth	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2021.					*/
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
    ObjectChangeAuth_In 	in;
    ObjectChangeAuth_Out 	out;
    TPMI_DH_OBJECT		parentHandle = TPM_RH_NULL;
    TPMI_DH_OBJECT		objectHandle = TPM_RH_NULL;
    const char			*objectPassword = NULL; 
    const char			*newPassword = NULL;
    const char			*newPasswordFilename = NULL;
    uint8_t			*newPasswordBuffer = NULL;
    size_t 			newPasswordBufferLength = 0;
    const char			*newPasswordPtr = NULL;
    const char			*privateKeyFilename = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &parentHandle );
	    }
	    else {
		printf("Missing parameter for -hp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &objectHandle);
	    }
	    else {
		printf("Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		objectPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		newPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipwdn") == 0) {
	    i++;
	    if (i < argc) {
		newPasswordFilename = argv[i];
	    }
	    else {
		printf("-ipwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opr") == 0) {
	    i++;
	    if (i < argc) {
		privateKeyFilename = argv[i];
	    }
	    else {
		printf("-opr option needs a value\n");
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
    if (parentHandle  == TPM_RH_NULL) {
	printf("Missing or bad parent handle parameter -hp\n");
	printUsage();
    }
    if (objectHandle == TPM_RH_NULL) {
	printf("Missing or bad object handle parameter -ho\n");
	printUsage();
    }
    if ((newPassword != NULL) && (newPasswordFilename != NULL)) {
	printf("Only one of -pwdn and -ipwdn can be specified\n");
	printUsage();
    }
    if (rc == 0) {
	in.objectHandle = objectHandle;
	in.parentHandle = parentHandle;
    }
    if (rc == 0) {
	/* use passsword from command line */
	if (newPassword != NULL) {
	    newPasswordPtr = newPassword;
	}
	/* use password from file */
	else if (newPasswordFilename != NULL) {
	    rc = TSS_File_ReadBinaryFile(&newPasswordBuffer,     /* freed @1 */
					 &newPasswordBufferLength,
					 newPasswordFilename);
	    if ((newPasswordBufferLength == 0) ||
		(newPasswordBuffer[newPasswordBufferLength-1] != '\0')) {
		printf("-ipwdn file must be nul terminated\n");
		printUsage();
	    }
	    newPasswordPtr = (const char *)newPasswordBuffer;
	}
	/* empty password */
	else {
	    newPasswordPtr = NULL;
	}
    }
    /* convert password string to TPM2B */
    if (rc == 0) {
	if (newPasswordPtr == NULL) {
	    in.newAuth.t.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&in.newAuth.b,
				      newPasswordPtr, sizeof(in.newAuth.t.buffer));
	}
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
			 TPM_CC_ObjectChangeAuth,
			 sessionHandle0, objectPassword, sessionAttributes0,
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
    /* save the private key */
    if ((rc == 0) && (privateKeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outPrivate,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshalu,
				     privateKeyFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("objectchangeauth: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("objectchangeauth: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(newPasswordBuffer);	/* @1 */

    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("objectchangeauth\n");
    printf("\n");
    printf("Runs TPM2_ObjectChangeAuth\n");
    printf("\n");
    printf("\t-hp\tparent handle\n");
    printf("\t-ho\tobject handle\n");
    printf("\t[-pwdo\tpassword for object (default empty)]\n");
    printf("\t[-pwdn\tnew password for object (default empty)]\n");
    printf("\t[-ipwdn\t new password file for object, nul terminated (default empty)]\n");
    printf("\t[-opr\tprivate key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
