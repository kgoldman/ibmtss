/********************************************************************************/
/*										*/
/*			   Nuvoton GetConfig 	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2getconfig.c 945 2017-02-27 23:24:31Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017					*/
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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>

#include "ntc2lib.h"

static void printUsage(void);
static void printHexResponse(NTC2_CFG_STRUCT *preConfig);
static TPM_RC verifyConfig(NTC2_CFG_STRUCT *preConfig, int verifyLocked);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    		/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NTC2_GetConfig_Out 		out;
    int 			verify = FALSE;
    int 			verifyLocked = FALSE;
  
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-verify") == 0) {
	    verify = TRUE;
	}
	else if (strcmp(argv[i],"-verifylocked") == 0) {
	    verify = TRUE;
	    verifyLocked = TRUE;
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
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 NULL,
			 NULL,
			 NTC2_CC_GetConfig,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printHexResponse(&out.preConfig);
    }
    if (rc == 0) {
	if (verify) {
	    rc = verifyConfig(&out.preConfig, verifyLocked);
	}
    }
    if (rc == 0) {
	if (verbose) printf("ntc2getconfig: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ntc2getconfig: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* verifyConfig() verifies the read preConfig against the System P defaults.

   If verifyLocked is FALSE, verifies that the preConfig is not locked.  If TRUE, verifies that it's
   locked.
*/

static TPM_RC verifyConfig(NTC2_CFG_STRUCT *preConfig, int verifyLocked)
{
    TPM_RC rc = 0;

    if (preConfig->i2cLoc1_2 != PREQUIRED_i2cLoc1_2) {
	printf("verifyConfig: i2cLoc1_2 %02x not equal to default %02x\n",
	       preConfig->i2cLoc1_2, PREQUIRED_i2cLoc1_2);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->i2cLoc3_4 != PREQUIRED_i2cLoc3_4) {
	printf("verifyConfig: i2cLoc3_4 %02x not equal to default %02x\n",
	       preConfig->i2cLoc3_4, PREQUIRED_i2cLoc3_4);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->AltCfg != PREQUIRED_AltCfg) {
	printf("verifyConfig: AltCfg %02x not equal to default %02x\n",
	       preConfig->AltCfg, PREQUIRED_AltCfg);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->Direction != PREQUIRED_Direction) {
	printf("verifyConfig: Direction %02x not equal to default %02x\n",
	       preConfig->Direction, PREQUIRED_Direction);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->PullUp != PREQUIRED_PullUp) {
	printf("verifyConfig: PullUp %02x not equal to default %02x\n",
	       preConfig->PullUp, PREQUIRED_PullUp);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->PushPull != PREQUIRED_PushPull) {
	printf("verifyConfig: PushPull %02x not equal to default %02x\n",
	       preConfig->PushPull, PREQUIRED_PushPull);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_A != PREQUIRED_CFG_A) {
	printf("verifyConfig: CFG_A %02x not equal to default %02x\n",
	       preConfig->CFG_A, PREQUIRED_CFG_A);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_B != PREQUIRED_CFG_B) {
	printf("verifyConfig: CFG_B %02x not equal to default %02x\n",
	       preConfig->CFG_B, PREQUIRED_CFG_B);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_C != PREQUIRED_CFG_C) {
	printf("verifyConfig: CFG_C %02x not equal to default %02x\n",
	       preConfig->CFG_C, PREQUIRED_CFG_C);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_D != PREQUIRED_CFG_D) {
	printf("verifyConfig: CFG_D %02x not equal to default %02x\n",
	       preConfig->CFG_D, PREQUIRED_CFG_D);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_E != PREQUIRED_CFG_E) {
	printf("verifyConfig: CFG_E %02x not equal to default %02x\n",
	       preConfig->CFG_E, PREQUIRED_CFG_E);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_F != PREQUIRED_CFG_F) {
	printf("verifyConfig: CFG_F %02x not equal to default %02x\n",
	       preConfig->CFG_F, PREQUIRED_CFG_F);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_G != PREQUIRED_CFG_G) {
	printf("verifyConfig: CFG_G %02x not equal to default %02x\n",
	       preConfig->CFG_G, PREQUIRED_CFG_G);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_H != PREQUIRED_CFG_H) {
	printf("verifyConfig: CFG_H %02x not equal to default %02x\n",
	       preConfig->CFG_H, PREQUIRED_CFG_H);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_I != PREQUIRED_CFG_I) {
	printf("verifyConfig: CFG_I %02x not equal to default %02x\n",
	       preConfig->CFG_I, PREQUIRED_CFG_I);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->CFG_J != PREQUIRED_CFG_J) {
	printf("verifyConfig: CFG_J %02x not equal to default %02x\n",
	       preConfig->CFG_J, PREQUIRED_CFG_J);
	rc = TPM_RC_VALUE;
    }
    if (preConfig->IsValid != PREQUIRED_IsValid) {
	printf("verifyConfig: IsValid %02x not equal to default %02x\n",
	       preConfig->IsValid, PREQUIRED_IsValid);
	rc = TPM_RC_VALUE;
    }
    if (verifyLocked) {
	if (preConfig->IsLocked != 0xaa) {
	    printf("verifyConfig: IsLocked is %02x not %02x\n",
		   preConfig->IsLocked, 0xaa);
	    rc = TPM_RC_VALUE;
	}
    }
    else {
	if (preConfig->IsLocked != 0xff) {
	    printf("verifyConfig: IsLocked %02x not %02x\n",
		   preConfig->IsLocked, 0xff);
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* printHexResponse() prints the read preConfig in a concise hex format */

static void printHexResponse(NTC2_CFG_STRUCT *preConfig)
{
    printf("i2cLoc1_2:\t%02x\n", preConfig->i2cLoc1_2);
    printf("i2cLoc3_4:\t%02x\n", preConfig->i2cLoc3_4);
    printf("AltCfg:\t\t%02x\n", preConfig->AltCfg);
    printf("Direction:\t%02x\n", preConfig->Direction);
    printf("PullUp:\t\t%02x\n", preConfig->PullUp);
    printf("PushPull:\t%02x\n", preConfig->PushPull);
    printf("CFG_A:\t\t%02x\n", preConfig->CFG_A);
    printf("CFG_B:\t\t%02x\n", preConfig->CFG_B);
    printf("CFG_C:\t\t%02x\n", preConfig->CFG_C);
    printf("CFG_D:\t\t%02x\n", preConfig->CFG_D);
    printf("CFG_E:\t\t%02x\n", preConfig->CFG_E);
    printf("CFG_F:\t\t%02x\n", preConfig->CFG_F);
    printf("CFG_G:\t\t%02x\n", preConfig->CFG_G);
    printf("CFG_H:\t\t%02x\n", preConfig->CFG_H);
    printf("CFG_I:\t\t%02x\n", preConfig->CFG_I);
    printf("CFG_J:\t\t%02x\n", preConfig->CFG_J);
    printf("IsValid:\t%02x\n", preConfig->IsValid);
    printf("IsLocked:\t%02x\n", preConfig->IsLocked);
    return;
}

static void printUsage(void)
{
    printf("\n");
    printf("ntc2getconfig\n");
    printf("\n");
    printf("Runs NTC2_GetConfig\n");
    printf("\n");
    printf("[-verify Verify results against System P default (default no verify)]\n");
    printf("[-verifylocked Verify that the preconfig is locked (default verify not locked)]\n");
    printf("\n");
    exit(1);
}
