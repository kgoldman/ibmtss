/********************************************************************************/
/*										*/
/*			   Import a PEM RSA keypair 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: importpem.c 885 2016-12-21 17:13:46Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
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

#include <openssl/pem.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include "ekutils.h"
#include "objecttemplates.h"

static TPM_RC convertRsaToPublic(TPM2B_PUBLIC 		*objectPublic,
				 TPMI_ALG_HASH		halg,
				 const RSA 		*rsaKey);
static TPM_RC convertRsaToPrivate(TPM2B_PRIVATE		*duplicate,
				  const char 		*keyPassword,
				  const RSA 		*rsaKey);
static void printUsage(void);

/* object type */

#define TYPE_ST		2
#define TYPE_SI		5

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Import_In 			in;
    Import_Out 			out;
    TPMI_DH_OBJECT		parentHandle = 0;
    const char			*parentPassword = NULL;
    const char			*pemKeyFilename = NULL;
    const char			*pemKeyPassword = "";	/* default empty password */
    const char			*outPublicFilename = NULL;
    const char			*outPrivateFilename = NULL;
    const char			*policyFilename = NULL;
    int				keyType = TYPE_SI;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    RSA				*rsaKey = NULL;
    FILE 			*pemKeyFile = NULL;
    
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    in.objectPublic.publicArea.objectAttributes.val = 0;
    /* default no DA protection */
    in.objectPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &parentHandle);
	    }
	    else {
		printf("Missing parameter for -hp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdp") == 0) {
	    i++;
	    if (i < argc) {
		parentPassword = argv[i];
	    }
	    else {
		printf("-pwdp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyFilename = argv[i];
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		outPublicFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opr") == 0) {
	    i++;
	    if (i < argc) {
		outPrivateFilename = argv[i];
	    }
	    else {
		printf("-opr option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pol") == 0) {
	    i++;
	    if (i < argc) {
		policyFilename = argv[i];
	    }
	    else {
		printf("-pol option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
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
	else if (strcmp(argv[i], "-da") == 0) {
	    in.objectPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_NODA;
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
    if (parentHandle == 0) {
	printf("Missing or bad object handle parameter -hp\n");
	printUsage();
    }
    if (pemKeyFilename == NULL) {
	printf("Missing parameter -ipem\n");
	printUsage();
    }
    if (outPublicFilename == NULL) {
	printf("Missing parameter -opu\n");
	printUsage();
    }
    if (outPrivateFilename == NULL) {
	printf("Missing parameter -opr\n");
	printUsage();
    }
    if (rc == 0) {
	in.parentHandle = parentHandle;
	in.encryptionKey.t.size = 0;
	in.inSymSeed.t.size = 0;
	in.symmetricAlg.algorithm = TPM_ALG_NULL;
	in.objectPublic.publicArea.nameAlg = nalg;
	/* permit password or HMAC authorization */
	in.objectPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	if (keyType == TYPE_SI) {
	    in.objectPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	}
	else {
	    in.objectPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	}
	/* instantiate optional policy */
	rc = getPolicy(&in.objectPublic.publicArea, policyFilename);
    }
    /*
      PEM to RSA
    */
    /* open the RSA PEM format file */
    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	rsaKey = PEM_read_RSAPrivateKey(pemKeyFile,		/* freed @1 */
					NULL, NULL, (void *)pemKeyPassword);
	if (rsaKey == NULL) {
	    printf("Error PEM_read_RSAPrivateKey reading key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    /* openssl RSA token to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaToPublic(&in.objectPublic,
				halg,
				rsaKey);
    }
    /* openssl RSA token to TPM2B_PRIVATE */
    if (rc == 0) {
	rc = convertRsaToPrivate(&in.duplicate,
				 pemKeyPassword,	/* for this example, use the same password */
				 rsaKey);
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
			 TPM_CC_Import,
			 sessionHandle0, parentPassword, sessionAttributes0,
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
    /* output the TPM2B_PUBLIC */
    if (rc == 0) {
	rc = TSS_File_WriteStructure(&in.objectPublic,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				     outPublicFilename);
    }
    /* output the TPM2B_PRIVATE, which is now wrapped by the parent */
    if (rc == 0) {
	rc = TSS_File_WriteStructure(&out.outPrivate,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal,
				     outPrivateFilename);
    }
    if (rc == 0) {
	if (verbose) printf("importpem: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("importpem: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (rsaKey != NULL) {
	RSA_free(rsaKey);			/* @1 */
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

/* convertRsaToPublic() converts from RSA to TPM2B_PUBLIC */

TPM_RC convertRsaToPublic(TPM2B_PUBLIC 		*objectPublic,
			  TPMI_ALG_HASH		halg,
			  const RSA 		*rsaKey)
{
    TPM_RC		rc = 0;
    int     		bytes;
    const BIGNUM 	*n;
    const BIGNUM 	*e;
    const BIGNUM 	*d;

    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_RSA;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */
	objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */
	/* always use RSASSA (sample code) */
	objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	objectPublic->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */
    }
    /* get the public modulus */
    /* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
    if (rc == 0) {
	rc = TSS_RSAGetKey(&n, &e, &d, NULL, NULL, rsaKey);
    }
    if (rc == 0) {
	bytes = BN_num_bytes(n);
	if ((size_t)bytes > sizeof(objectPublic->publicArea.unique.rsa.t.buffer)) {
	    printf("Error, public key modulus %d greater than %lu\n", bytes,
		   (unsigned long)sizeof(objectPublic->publicArea.unique.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
	else {
	    objectPublic->publicArea.unique.rsa.t.size =
		BN_bn2bin(n, (uint8_t *)&objectPublic->publicArea.unique.rsa.t.buffer);
	}
    }
    if (rc == 0) {
	objectPublic->publicArea.parameters.rsaDetail.keyBits = bytes * 8;	
	objectPublic->publicArea.parameters.rsaDetail.exponent = 0;
    }
    return rc;
}

/* convertRsaToPrivate() converts from RSA to TPM2B_PRIVATE */

static TPM_RC convertRsaToPrivate(TPM2B_PRIVATE	*duplicate,
				  const char 	*keyPassword,
				  const RSA 	*rsaKey)
{
    TPM_RC		rc = 0;
    TPM2B_SENSITIVE	bSensitive;
    TPMT_SENSITIVE	tSensitive;
    const BIGNUM 	*p;
    const BIGNUM 	*q;
    int     		bytes;
    
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */	

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_RSA;
	tSensitive.seedValue.b.size = 0;		/* FIXME check this */
	/* key password converted to TPM2B */
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, keyPassword, sizeof(TPMU_HA));
    }
    /* get the private primes */
    if (rc == 0) {
	rc = TSS_RSAGetKey(NULL, NULL, NULL, &p, &q, rsaKey);
    }
    if (rc == 0) {
	bytes = BN_num_bytes(p);
	if ((size_t)bytes > sizeof(tSensitive.sensitive.rsa.t.buffer)) {
	    printf("Error, private key modulus %d greater than %lu\n", bytes,
		   (unsigned long)sizeof(tSensitive.sensitive.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
	else {
	    /* convert the bignum to a TPM2B */
	    /* TPMU_SENSITIVE_COMPOSITE	sensitive; */
	    tSensitive.sensitive.rsa.t.size =
		BN_bn2bin(p, (uint8_t *)&tSensitive.sensitive.rsa.t.buffer);
	}
    }
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */	
    if (rc == 0) {
	int32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	uint8_t *buffer = bSensitive.b.buffer;			/* pointer that can move */
	bSensitive.t.size = 0;					/* required before marshaling */
	rc = TSS_TPMT_SENSITIVE_Marshal(&tSensitive,
					&bSensitive.b.size,	/* marshaled size */
					&buffer,		/* marshal here */
					&size);			/* max size */
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	int32_t size = sizeof(duplicate->t.buffer);	/* max size */
	uint8_t *buffer = duplicate->t.buffer;		/* pointer that can move */
	duplicate->t.size = 0;				/* required before marshaling */
	rc = TSS_TPM2B_PRIVATE_Marshal((TPM2B_PRIVATE *)&bSensitive,
				       &duplicate->t.size,	/* marshaled size */
				       &buffer,		/* marshal here */
				       &size);		/* max size */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("Import PEM\n");
    printf("\n");
    printf("Runs TPM2_Import for a PEM RSA key\n");
    printf("\n");
    printf("\t-hp parent handle\n");
    printf("\t[-pwdp password for parent (default empty)]\n");
    printf("\t-ipem PEM format RSA key pair\n");
    printf("\t[-pwdk password for key (default empty)]\n");
    printf("\t-opu public area file name\n");
    printf("\t-opr private area file name\n");
    printf("\t[-nalg name hash algorithm [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-halg scheme hash algorithm [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-pol policy file (default empty)]\n");
    printf("\t[-da object subject to DA protection (default no)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t\t01 continue\n");
    printf("\t\t20 command decrypt\n");
    printf("\t\t40 response encrypt\n");
    exit(1);	
}
