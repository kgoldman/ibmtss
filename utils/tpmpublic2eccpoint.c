/********************************************************************************/
/*										*/
/*		    TPM public key TPM2B_PUBLIC to TPM2B_ECC_POINT 		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmpublic2eccpoint.c 1072 2017-09-11 19:55:31Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2017						*/
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
#include <stdint.h>

#include <tss2/tsserror.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tssmarshal.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    const char			*publicKeyFilename = NULL;
    const char			*pointFilename = NULL;
    TPM2B_PUBLIC		public;
    TPM2B_ECC_POINT 		eccPoint2b;
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pt") == 0) {
	    i++;
	    if (i < argc) {
		pointFilename = argv[i];
	    }
	    else {
		printf("-pt option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (publicKeyFilename == NULL) {
	printf("Missing public key parameter -ipu\n");
	printUsage();
    }
    if (pointFilename == NULL) {
	printf("Missing point file name parameter -pt\n");
	printUsage();
    }
    /* read the TPM public key to a structure */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&public,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    publicKeyFilename);
    }
    if (rc == 0) {
	if (public.publicArea.type != TPM_ALG_ECC) {
	    printf("Public key parameter -ipu type %04x is not TPM_ALG_ECC\n",
		   public.publicArea.type);
	    printUsage();
	}
    }
    if (rc == 0) {
	/* copy the TPMS_ECC_POINT */
	eccPoint2b.point = public.publicArea.unique.ecc;
	/* TSS_TPM2B_ECC_POINT_Marshal() fills in the redundant TPM2B_ECC_POINT size */
	rc = TSS_File_WriteStructure(&eccPoint2b,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshal,
				     pointFilename);
	
    }
    if (rc == 0) {
	if (verbose) printf("tpmpublic2eccpoint: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("tpmpublic2eccpoint: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("tpmpublic2eccpoint\n");
    printf("\n");
    printf("Converts an EC TPM2B_PUBLIC to TPM2B_ECC_POINT.  The intended use case\n");
    printf("is to convert the public key output of certain commands (TPM2_CreatePrimary,\n");
    printf("TPM2_Create, TPM2_CreateLoaded, TPM2_ReadPublic) to a format useful for\n");
    printf("TPM2_ZGen_2Phase\n");
    printf("\n");
    printf("\n");
    printf("\t-ipu EC public key input file in TPM TPM2B_PUBLIC format\n");
    printf("\t-pt EC public key output file in TPM TPM2B_ECC_POINT format\n");
    exit(1);	
}
