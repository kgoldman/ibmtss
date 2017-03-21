/********************************************************************************/
/*										*/
/*			   Load External					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadexternal.c 945 2017-02-27 23:24:31Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
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
  DER example:

  Create a key pair in PEM format
  
  > openssl genrsa -out keypair.pem -aes256 -passout pass:rrrr 2048

  Convert to plaintext DER format

  > openssl rsa -inform pem -outform der -in keypair.pem -out keypair.der -passin pass:rrrr


*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>
#include "cryptoutils.h"
#include "ekutils.h"

static void printUsage(void);
TPM_RC loadExternalTPM(LoadExternal_In 	*in,
		       const char	*publicKeyFilename);
TPM_RC loadExternalPEMRSA(LoadExternal_In 	*in,
			  int			keyType,
			  TPMI_ALG_HASH 	nalg,
			  TPMI_ALG_HASH		halg,
			  const char		*pemKeyFilename);
TPM_RC loadExternalPEMECC(LoadExternal_In 	*in,
			  int			keyType,
			  TPMI_ALG_HASH 	nalg,
			  TPMI_ALG_HASH		halg,
			  const char		*pemKeyFilename);
TPM_RC loadExternalDer(LoadExternal_In 	*in,
		       int		keyType,
		       TPMI_ALG_HASH 	nalg,
		       TPMI_ALG_HASH	halg,
		       const char	*derKeyFilename);

/* object type */

#define TYPE_ST		2
#define TYPE_SI		5

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    LoadExternal_In 		in;
    LoadExternal_Out 		out;
    char 			hierarchyChar = 0;
    TPMI_RH_HIERARCHY		hierarchy = TPM_RH_NULL;
    int				keyType = TYPE_SI;
    uint32_t 			keyTypeSpecified = 0;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    const char			*publicKeyFilename = NULL;
    const char			*derKeyFilename = NULL;
    const char			*pemKeyFilename = NULL;
    unsigned int		inputCount = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hi") == 0) {
	    i++;
	    if (i < argc) {
		if (argv[i][0] != 'e' && argv[i][0] != 'o' &&
		    argv[i][0] != 'p' && argv[i][0] != 'h') {
		    printUsage();
		}
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
		printUsage();
	    }
	    
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else {
		    printf("Bad parameter for -halg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-nalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    nalg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    nalg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    nalg = TPM_ALG_SHA384;
		}
		else {
		    printf("Bad parameter for -nalg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-nalg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
	}
	else if (strcmp(argv[i], "-st") == 0) {
	    keyType = TYPE_ST;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-si") == 0) {
	    keyType = TYPE_SI;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ider") == 0) {
	    i++;
	    if (i < argc) {
		derKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ider option needs a value\n");
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
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (inputCount != 1) {
	printf("Missing or too many parameters -ipu, -ipem, -ider\n");
	printUsage();
    }
    if (keyTypeSpecified > 1) {
	printf("Too many key attributes\n");
	printUsage();
    }
    /* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
    if (rc == 0) {
	if (hierarchyChar == 'e') {
	    hierarchy = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    hierarchy = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    hierarchy = TPM_RH_PLATFORM;
	}
	else if (hierarchyChar == 'n') {
	    hierarchy = TPM_RH_NULL;
	}
    }
    if (rc == 0) {
	/* TPM format key, output from create */
	if (publicKeyFilename != NULL) {
	    rc = loadExternalTPM(&in,
				 publicKeyFilename);
	}
	/* PEM format, output from e.g. openssl */
	else if (pemKeyFilename != NULL) {
	    if (algPublic == TPM_ALG_RSA) {
		rc = loadExternalPEMRSA(&in,
					keyType,
					nalg,
					halg,
					pemKeyFilename);
	    }
	    /* TPM_ALG_ECC */
	    else {	
		rc = loadExternalPEMECC(&in,
					keyType,
					nalg,
					halg,
					pemKeyFilename);
	    }
	}
	else if (derKeyFilename != NULL) {
	    rc = loadExternalDer(&in,
				 keyType,
				 nalg,
				 halg,
				 derKeyFilename);
	}
	else {
	    printf("Failure parsing -ipu, -ipem, -ider\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	in.hierarchy = hierarchy;
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
			 TPM_CC_LoadExternal,
			 sessionHandle0, NULL, sessionAttributes0,
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
	printf("Handle %08x\n", out.objectHandle);
	if (verbose) printf("loadexternal: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("loadexternal: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* loadExternalTPM() loads a public key saved in TPM format

 */

TPM_RC loadExternalTPM(LoadExternal_In 	*in,
		       const char	*publicKeyFilename)
{
    TPM_RC			rc = 0;

    if (rc == 0) {
	in->inPrivate.t.size = 0;
	rc = TSS_File_ReadStructure(&in->inPublic,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    publicKeyFilename);
    }
    return rc;
}

/* loadExternalDer() loads an RSA signing keypair stored in plaintext DER format */

TPM_RC loadExternalDer(LoadExternal_In 	*in,
		       int		keyType,
		       TPMI_ALG_HASH 	nalg,
		       TPMI_ALG_HASH	halg,
		       const char	*derKeyFilename)
{
    TPM_RC		rc = 0;
    RSA 		*rsaKey = NULL;
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;
	d2i_RSAPrivateKey(&rsaKey, &tmpPtr, derSize);	/* freed @2 */
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(NULL,
				    &in->inPrivate,
				    rsaKey,
				    NULL);		/* Empty Auth */	
	in->inPrivate.t.size = 1;			/* mark that private area should be used */
    }	
    if (rc == 0) {
	rc = convertRsaKeyToPublic(&in->inPublic,
				   keyType,
				   nalg,
				   halg,
				   rsaKey);
    }
    free(derBuffer);			/* @1 */
    if (rsaKey != NULL) {
	RSA_free(rsaKey);		/* @2 */
    }
    return rc;
}

/* loadExternalPEMRSA() loads an RSA signing public key stored in PEM format */

TPM_RC loadExternalPEMRSA(LoadExternal_In 	*in,
			  int			keyType,
			  TPMI_ALG_HASH 	nalg,
			  TPMI_ALG_HASH		halg,
			  const char		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
    RSA		*rsaKey = NULL;

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(&in->inPublic,
				   keyType,
				   nalg,
				   halg,
				   rsaKey);
    }
    if (rc == 0) {
	in->inPrivate.t.size = 0;
    }
    if (rsaKey != NULL) {
	RSA_free(rsaKey);		/* @2 */
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

/* loadExternalPEMECC() loads an ECC P256 signing public key stored in PEM format */

TPM_RC loadExternalPEMECC(LoadExternal_In 	*in,
			  int			keyType,
			  TPMI_ALG_HASH 	nalg,
			  TPMI_ALG_HASH		halg,
			  const char		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY  	*evpPkey = NULL;
    EC_KEY 	*ecKey = NULL;

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @2 */
				   evpPkey);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(&in->inPublic,
				  keyType,
				  nalg,
				  halg,
				  ecKey);
    }
    if (rc == 0) {
	in->inPrivate.t.size = 0;
    }
    EC_KEY_free(ecKey);   		/* @2 */
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("loadexternal\n");
    printf("\n");
    printf("Runs TPM2_LoadExternal\n");
    printf("\n");
    printf("\t[-hi hierarchy (e, o, p, n) (default NULL)]\n");
    printf("\t[-nalg name hash algorithm [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-halg [sha256, sha1] (default sha256)]\n");
    printf("\t[Asymmetric Key Algorithm]\n");
    printf("\t\t[-rsa (default)]\n");
    printf("\t\t[-ecc curve (P256)]\n");
    printf("\t-ipu public key file name\n");
    printf("\t-ipem PEM format public key file name\n");
    printf("\t-ider DER format plaintext key pair file name\n");
    printf("\t[-si signing (default)]\n");
    printf("\t[-st storage]\n");
    exit(1);	
}
