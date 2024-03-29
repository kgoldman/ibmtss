/********************************************************************************/
/*										*/
/*			    HierarchyChangeAuth	 				*/
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

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    HierarchyChangeAuth_In 	in;
    char 			hierarchyChar = 0;
    const char			*newPassword = NULL; 
    const char			*newPasswordFilename = NULL;
    const char			*authPassword = NULL; 
    const char			*authPasswordFilename = NULL;
    /* authPasswordPtr is used as the command auth value.  It is either the supplied authPassword
       string, the password read from the authPasswordFilename file, or NULL */
    const char			*authPasswordPtr = NULL; 
    uint8_t			*authPasswordBuffer = NULL;		/* for the free */
    size_t 			authPasswordLength = 0;
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
	if (strcmp(argv[i],"-hi") == 0) {
	    i++;
	    if (i < argc) {
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
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
	else if (strcmp(argv[i],"-pwda") == 0) {
	    i++;
	    if (i < argc) {
		authPassword = argv[i];
	    }
	    else {
		printf("-pwda option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdni") == 0) {
	    i++;
	    if (i < argc) {
		newPasswordFilename = argv[i];
	    }
	    else {
		printf("pwdni -option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdai") == 0) {
	    i++;
	    if (i < argc) {
		authPasswordFilename = argv[i];
	    }
	    else {
		printf("-pwdai option needs a value\n");
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
    /* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
    if (rc == 0) {
	if (hierarchyChar == 'l') {
	    in.authHandle = TPM_RH_LOCKOUT;
	}
	else if (hierarchyChar == 'e') {
	    in.authHandle = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    in.authHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    in.authHandle = TPM_RH_PLATFORM;
	}
	else {
	    printf("Missing or illegal -hi\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	if ((newPassword != NULL) && (newPasswordFilename != NULL)) {
	    printf("Cannot specify both -pwdn and -pwdni\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	if ((authPassword != NULL) && (authPasswordFilename != NULL)) {
	    printf("Cannot specify both -pwda and -pwdai\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	/* new auth from string */
	if (newPassword != NULL) {
	    /* convert password string to TPM2B */
	    rc = TSS_TPM2B_StringCopy(&in.newAuth.b,
				      newPassword, sizeof(in.newAuth.t.buffer));
	}
	/* new auth from file */
	else if (newPasswordFilename != NULL) {
	    uint8_t			*buffer = NULL;		/* for the free */
	    size_t 			length = 0;
	    /* read new auth value from the file */
	    if (rc == 0) {
		rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
					     &length,
					     newPasswordFilename);
		if ((length == 0) ||
		    (buffer[length-1] != '\0')) {
		    printf("-pwdni file must be nul terminated\n");
		    printUsage();
		}
	    }
	    /* convert password file string to TPM2B */
	    if (rc == 0) {
		rc = TSS_TPM2B_StringCopy(&in.newAuth.b,
					  (const char *)buffer, sizeof(in.newAuth.t.buffer));
	    }
	    free(buffer);	/* @1 */
	    buffer = NULL;
	}
	/* no new auth specified */
	else {
	    in.newAuth.t.size = 0;
	}
    }
    if (rc == 0) {
	/* command auth from string */
	if (authPassword != NULL) {
	    authPasswordPtr = authPassword; 
	}
	/* command auth from file */
	else if (authPasswordFilename != NULL) {
	    if (rc == 0) {
		/* must be freed by caller */
		rc = TSS_File_ReadBinaryFile(&authPasswordBuffer,
					     &authPasswordLength,
					     authPasswordFilename);
		if ((authPasswordLength > sizeof(TPMU_HA)) ||
		    (authPasswordLength == 0) ||
		    (authPasswordBuffer[authPasswordLength -1] != '\0')) {
		    printf("-pwdai file must be nul terminated\n");
		    printUsage();
		}
	    }
	    if (rc == 0) {
		authPasswordPtr = (const char *)authPasswordBuffer;
	    }
	}
	/* no command auth specified */
	else {
	    authPasswordPtr = NULL;
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_HierarchyChangeAuth,
			 sessionHandle0, authPasswordPtr, sessionAttributes0,
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
    if (rc == 0) {
	if (tssUtilsVerbose) printf("hierarchychangeauth: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("hierarchychangeauth: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(authPasswordBuffer);
    authPasswordBuffer = NULL;
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("hierarchychangeauth\n");
    printf("\n");
    printf("Runs TPM2_HierarchyChangeAuth\n");
    printf("\n");
    printf("\t-hi\thierarchy (l, e, o, p)\n");
    printf("\t\tl lockout, e endorsement, o owner, p platform\n");
    printf("\t-pwdn\tnew authorization password (default empty)\n");
    printf("\t-pwdni\tnew authorization password file name (default empty)\n");
    printf("\t-pwda\tauthorization password (default empty)\n");
    printf("\t-pwdai\tauthorization password file name (default empty)\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    exit(1);	
}
