/********************************************************************************/
/*										*/
/*			   Nuvoton Lock Preconfig  				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2lockconfig.c 813 2016-11-16 22:24:37Z kgoldman $		*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2016				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
/********************************************************************************/

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>

#include "ntc2lib.h"

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    		/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    int				lock = FALSE;

    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-lock") == 0) {
	    lock = TRUE;
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
    if (!lock) {
	printf("\nntc2lockpreconfig requires -lock\n");
	printUsage();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 NULL,
			 NULL,
			 NTC2_CC_LockPreConfig,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("ntc2lockpreconfig: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ntc2lockpreconfig: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("ntc2lockpreconfig\n");
    printf("\n");
    printf("Runs NTC2_LockPreConfig\n");
    printf("\n");
    printf("-lock (required)\n");
    printf("\n");
    exit(1);
}

