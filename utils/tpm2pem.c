/********************************************************************************/
/*										*/
/*		    TPM public key TPM2B_PUBLIC to PEM 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm2pem.c 1065 2017-08-25 19:19:50Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017					*/
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

/* Converts a TPM public key TPM2B_PUBLIC to PEM */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

/* #include <tss2/tss.h> */
#include <tss2/tsserror.h>
#include <tss2/tssutils.h>
#include <tss2/tsscrypto.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

#include "cryptoutils.h"

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    const char			*publicKeyFilename = NULL;
    const char			*pemFilename = NULL;
    TPM2B_PUBLIC 		public;

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
	else if (strcmp(argv[i],"-opem") == 0) {
	    i++;
	    if (i < argc) {
		pemFilename = argv[i];
	    }
	    else {
		printf("-opem option needs a value\n");
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
	printf("Missing private key parameter -ipu\n");
	printUsage();
    }
    if (pemFilename == NULL) {
	printf("Missing PEM file name parameter -opem\n");
	printUsage();
    }
    /* read the TPM public key to a structure */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&public,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    publicKeyFilename);
    }
    /* convert to PEM format and write file */
    if (rc == 0) {
	rc = convertPublicToPEM(&public, pemFilename);
    }
    if (rc == 0) {
	if (verbose) printf("tpm2pem: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("tpm2pem: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("tpm2pem\n");
    printf("\n");
    printf("Converts an RSA or EC TPM2B_PUBLIC to PEM\n");
    printf("\n");
    printf("\t-ipu public key input file in TPM format\n");
    printf("\t-opem public key output file in PEM format\n");
    exit(1);	
}
