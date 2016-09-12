/********************************************************************************/
/*										*/
/*			    Create 						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: create.c 682M 2016-08-09 17:30:16Z (local) $			*/
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

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>

static void printUsage(void);
static void asymPublicTemplate(Create_In *in,
			       int type,
			       TPMI_ALG_PUBLIC algPublic,
			       TPMI_ECC_CURVE curveID,			       
			       TPMI_ALG_HASH nalg,
			       TPMI_ALG_HASH halg);
static void symmetricCipherTemplate(Create_In *in,
				    TPMI_ALG_HASH nalg,
				    int rev116);
static void keyedHashPublicTemplate(Create_In *in,
				    TPMI_ALG_HASH nalg,
				    TPMI_ALG_HASH halg);
static void blPublicTemplate(Create_In *in,
			     TPMI_ALG_HASH nalg);
/* object type */

#define TYPE_BL		1
#define TYPE_ST		2
#define TYPE_DEN	3	
#define TYPE_DEO	4
#define TYPE_SI		5
#define TYPE_SIR	6
#define TYPE_GP		7
#define TYPE_DES	8
#define TYPE_KH		9

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Create_In 			in;
    Create_Out 			out;
    TPMI_DH_OBJECT		parentHandle = 0;
    int				keyType = 0;
    uint32_t 			keyTypeSpecified = 0;
    int				rev116 = FALSE;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ECC_CURVE		curveID = TPM_ECC_NONE;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    const char			*policyFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*privateKeyFilename = NULL;
    const char 			*dataFilename = NULL;
    const char			*keyPassword = NULL; 
    const char			*parentPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    in.inPublic.t.publicArea.objectAttributes.val = 0;
    in.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
 	
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
	else if (strcmp(argv[i], "-bl") == 0) {
	    keyType = TYPE_BL;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-den") == 0) {
	    keyType = TYPE_DEN;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-deo") == 0) {
	    keyType = TYPE_DEO;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-des") == 0) {
	    keyType = TYPE_DES;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-st") == 0) {
	    keyType = TYPE_ST;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-si") == 0) {
	    keyType = TYPE_SI;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-sir") == 0) {
	    keyType = TYPE_SIR;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-kh") == 0) {
	    keyType = TYPE_KH;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-gp") == 0) {
	    keyType = TYPE_GP;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-116") == 0) {
	    rev116 = TRUE;
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"bnp256") == 0) {
		    curveID = TPM_ECC_BN_P256;
		}
		else if (strcmp(argv[i],"nistp256") == 0) {
		    curveID = TPM_ECC_NIST_P256;
		}
		else if (strcmp(argv[i],"nistp384") == 0) {
		    curveID = TPM_ECC_NIST_P384;
		}
		else {
		    printf("Bad parameter for -ecc\n");
		    printUsage();
		}
	    }
	    else {
		printf("-cv option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-kt") == 0) {
	    i++;
	    if (i < argc) {
		switch (argv[i][0]) {
		  case 'f':
		    in.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		    break;
		  case 'p':
		    in.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		    break;
		  default:
		    printf("Bad parameter for -kt\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -kt\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-da") == 0) {
	    in.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_NODA;
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
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
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
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
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
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		dataFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
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
    if (parentHandle == 0) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (keyTypeSpecified != 1) {
	printf("Missing key attributes\n");
	printUsage();
    }
    switch (keyType) {
      case TYPE_BL:
	if (dataFilename == NULL) {
	    printf("-bl needs -if (sealed data object needs data to seal)\n");
	    printUsage();
	}
	break;
      case TYPE_ST:
      case TYPE_DEN:
      case TYPE_DEO:
      case TYPE_SI:
      case TYPE_SIR:
      case TYPE_GP:
	if (dataFilename != NULL) {
	    printf("asymmetric key cannot have -if (sensitive data)\n");
	    printUsage();
	}
      case TYPE_DES:
      case TYPE_KH:
	/* inSensitive optional for symmetric keys */
	break;
    }
    if (rc == 0) {
	in.parentHandle = parentHandle;
    }
    /* Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive */
    if (rc == 0) {
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	if (keyPassword == NULL) {
	    in.inSensitive.t.sensitive.userAuth.t.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&in.inSensitive.t.sensitive.userAuth.b,
				      keyPassword, sizeof(TPMU_HA));
	}
    }
    if (rc == 0) {
	/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure data */
	if (dataFilename != NULL) {
	    rc = TSS_File_Read2B(&in.inSensitive.t.sensitive.data.b,
				 MAX_SYM_DATA,
				 dataFilename);
	}
	else {
	    in.inSensitive.t.sensitive.data.t.size = 0;
	}
    }
    /* optional authorization policy */
    if (policyFilename != NULL) {
	rc = TSS_File_Read2B(&in.inPublic.t.publicArea.authPolicy.b,
			     sizeof(TPMU_HA),
			     policyFilename);
    }
    else {
	in.inPublic.t.publicArea.authPolicy.t.size = 0;	/* default empty policy */
    }
    /* TPM2B_PUBLIC */
    if (rc == 0) {
	switch (keyType) {
	  case TYPE_BL:
	    blPublicTemplate(&in, nalg);
	    break;
	  case TYPE_ST:
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_SI:
	  case TYPE_SIR:
	  case TYPE_GP:
	    asymPublicTemplate(&in, keyType, algPublic, curveID, nalg, halg);
	    break;
	  case TYPE_DES:
	    symmetricCipherTemplate(&in, nalg, rev116);
	    break;
	  case TYPE_KH:
	    keyedHashPublicTemplate(&in, nalg, halg);
	    break;
	} 
    }
    if (rc == 0) {
	/* TPM2B_DATA outsideInfo */
	in.outsideInfo.t.size = 0;
	/* Table 102 - TPML_PCR_SELECTION creationPCR */
	in.creationPCR.count = 0;
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
			 TPM_CC_Create,
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
    /* save the private key */
    if ((rc == 0) && (privateKeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outPrivate,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal,
				     privateKeyFilename);
    }
    /* save the public key */
    if ((rc == 0) && (publicKeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outPublic,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				     publicKeyFilename);
    }
    if (rc == 0) {
	if (verbose) printf("create: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("create: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* asymPublicTemplate() is a template for an ECC or RSA 2048 key.

   It can create these types:

   TYPE_ST:   RSA storage key
   TYPE_DEN:  RSA decryption key (not storage key, NULL scheme)
   TYPE_DEO:  RSA decryption key (not storage key, OAEP scheme)
   TYPE_SI:   RSA signing key (unrestricted)
   TYPE_SIR:  RSA signing key (restricted)
   TYPE_GP:   RSA general purpose key

   If restricted, it uses the RSASSA padding scheme
*/

static void asymPublicTemplate(Create_In *in,
			       int keyType,
			       TPMI_ALG_PUBLIC algPublic,
			       TPMI_ECC_CURVE curveID,			       
			       TPMI_ALG_HASH nalg,
			       TPMI_ALG_HASH halg)
{
    /* Table 185 - TPM2B_PUBLIC inPublic */
    /* Table 184 - TPMT_PUBLIC publicArea */
    in->inPublic.t.publicArea.type = algPublic;		/* RSA or ECC */
    in->inPublic.t.publicArea.nameAlg = nalg;

    /* Table 32 - TPMA_OBJECT objectAttributes */
    in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;

    switch (keyType) {
      case TYPE_DEN:
      case TYPE_DEO:
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	break;
      case TYPE_ST:
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	break;
      case TYPE_SI:
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
 	break;
      case TYPE_SIR:
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	break;
      case TYPE_GP:
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	break;
    }	

    /* Table 72 -  TPM2B_DIGEST authPolicy */
    /* policy set separately */

    /* Table 182 - Definition of TPMU_PUBLIC_PARMS parameters */
    if (algPublic == TPM_ALG_RSA) {
	/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS rsaDetail */
    	/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	switch (keyType) {
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_SI:
	  case TYPE_SIR:
	  case TYPE_GP:
	    /* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
	    in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	  case TYPE_ST:
	    in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	    /* Table 125 - TPMU_SYM_KEY_BITS keyBits */
	    in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	    /* Table 126 - TPMU_SYM_MODE mode */
	    in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    break;
	}

	/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME scheme */
	switch (keyType) {
	  case TYPE_DEN:
	  case TYPE_GP:
	  case TYPE_ST:
	  case TYPE_SI:
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	    break;
	  case TYPE_DEO:
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_OAEP;
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME details */
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME rsassa */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH hashAlg */
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.details.oaep.hashAlg = halg;
	    break;
	  case TYPE_SIR:
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME details */
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME rsassa */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH hashAlg */
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	    break;
	}
	
	/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type keyBits */
	in->inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
	in->inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	in->inPublic.t.publicArea.unique.rsa.t.size = 0;
    }
    else {	/* algPublic == TPM_ALG_ECC */
	/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure eccDetail */
   	/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	switch (keyType) {
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_SI:
	  case TYPE_SIR:
	  case TYPE_GP:
	    /* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
	    in->inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	  case TYPE_ST:
	    in->inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	    /* Table 125 - TPMU_SYM_KEY_BITS keyBits */
	    in->inPublic.t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	    /* Table 126 - TPMU_SYM_MODE mode */
	    in->inPublic.t.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    break;
	}
	/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure scheme */
	/* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type scheme */
	switch (keyType) {
	  case TYPE_GP:
	  case TYPE_SI:
	    in->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	    /* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */
	    /* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> curveID */
	    in->inPublic.t.publicArea.parameters.eccDetail.curveID = curveID;
	    /* Table 150 - Definition of TPMT_KDF_SCHEME Structure kdf */
	    /* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */
	    in->inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	    break;
	  case TYPE_SIR:
	    in->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME details */
	    /* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */
	    in->inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
	    /* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */
	    /* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> curveID */
	    in->inPublic.t.publicArea.parameters.eccDetail.curveID = curveID;
	    /* Table 150 - Definition of TPMT_KDF_SCHEME Structure kdf */
	    /* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */
	    in->inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	    /* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */
	    /* Table 148 - Definition of Types for KDF Schemes, hash-based key-
	       or mask-generation functions */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure hashAlg */
	    in->inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
	    break;
	  case TYPE_DEN:
	  case TYPE_DEO:
	    /* FIXME keys other than signing are wrong, not implemented yet */
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	    /* Table 152 - Definition of TPMU_ASYM_SCHEME details */
	    break;
	  case TYPE_ST:
	    /* FIXME keys other than signing are wrong, not implemented yet */
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	    break;
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	in->inPublic.t.publicArea.unique.ecc.x.t.size = 0;
	in->inPublic.t.publicArea.unique.ecc.y.t.size = 0;
    }
    return;
}

/* symmetricCipherTemplate() is a template for an AES 128 CFB key */

static void symmetricCipherTemplate(Create_In *in,
				    TPMI_ALG_HASH nalg,
				    int rev116)
{
    /* Table 185 - TPM2B_PUBLIC inPublic */
    /* Table 184 - TPMT_PUBLIC publicArea */
    {
	in->inPublic.t.publicArea.type = TPM_ALG_SYMCIPHER;
	in->inPublic.t.publicArea.nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	/* rev 116 used DECRYPT for both decrypt and encrypt.  After 116, encrypt required SIGN */
	if (!rev116) {
	    /* actually encrypt */
	    in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	}
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS parameters */
	{
	    /* Table 131 - Definition of TPMS_SYMCIPHER_PARMS symDetail */
	    {
		/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT sym */
		/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */
		in->inPublic.t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
		/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
		in->inPublic.t.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
		/* Table 126 - Definition of TPMU_SYM_MODE Union */
		in->inPublic.t.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
	    }
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	in->inPublic.t.publicArea.unique.sym.t.size = 0; 
    }
    return;
}

/* keyedHashPublicTemplate() is a template for a HMAC key

   The key is not restricted
*/

static void keyedHashPublicTemplate(Create_In *in,
				    TPMI_ALG_HASH nalg,
				    TPMI_ALG_HASH halg)
{
    /* Table 185 - TPM2B_PUBLIC inPublic */
    /* Table 184 - TPMT_PUBLIC publicArea */
    {
	/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */
	in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	in->inPublic.t.publicArea.nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	{
	    /* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	    /* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */
	    /* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */
	    /* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */
	    in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
	    /* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */
	    /* Table 138 - Definition of Types for HMAC_SIG_SCHEME */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = halg;
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	in->inPublic.t.publicArea.unique.sym.t.size = 0; 
    }
}

/* blPublicTemplate() is a template for a sealed data blob.

*/

static void blPublicTemplate(Create_In *in,
			     TPMI_ALG_HASH nalg)
{
    /* Table 185 - TPM2B_PUBLIC inPublic */
    /* Table 184 - TPMT_PUBLIC publicArea */
    {
	/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */
	in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	in->inPublic.t.publicArea.nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	in->inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	{
	    /* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	    /* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */
	    /* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */
	    /* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */
	    in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
	    /* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */
	}
    }
    /* Table 177 - TPMU_PUBLIC_ID unique */
    /* Table 72 - Definition of TPM2B_DIGEST Structure */
    in->inPublic.t.publicArea.unique.sym.t.size = 0; 
}

static void printUsage(void)
{
    printf("\n");
    printf("create\n");
    printf("\n");
    printf("Runs TPM2_Create\n");
    printf("\n");
    printf("\t-hp parent handle\n");
    printf("\n");
    printf("\tAsymmetric Key Algorithm\n");
    printf("\t\t-rsa (default)\n");
    printf("\t\t-ecc curve\n");
    printf("\t\t\tbnp256\n");
    printf("\t\t\tnistp256\n");
    printf("\t\t\tnistp384\n");
    printf("\n");
    printf("\tKey attributes\n");
    printf("\n");
    printf("\t\t-bl data blob for unseal\n");
    printf("\t\t\t-if data file name\n");
    printf("\t\t-den decryption, RSA, not storage, NULL scheme\n");
    printf("\t\t-deo decryption, RSA, not storage, OAEP scheme\n");
    printf("\t\t-des encryption/decryption, AES symmetric\n");
    printf("\t\t\t[-116 for TPM rev 116 compatibility]\n");
    printf("\t\t-st storage\n");
    printf("\t\t-si signing\n");
    printf("\t\t-sir restricted signing\n");
    printf("\t\t-kh keyed hash (hmac)\n");
    printf("\t\t-gp general purpose, not storage\n");
    printf("\n");
    printf("\t\t-kt (can be specified more than once)\n"
	   "\t\t\tf fixedTPM \n"
	   "\t\t\tp fixedParent \n");
    printf("\t\t[-da object subject to DA protection) (default no)]\n");
    printf("\n");
    printf("\t[-nalg name hash algorithm [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-halg scheme hash algorithm [sha1, sha256, sha384] (default sha256)]\n");
    printf("\n");
    printf("\t[-pwdk password for key (default empty)]\n");
    printf("\t[-pwdp password for parent key (default empty)]\n");
    printf("\t[-pol policy file (default empty)]\n");
    printf("\n");
    printf("\t[-opu public key file name (default do not save)]\n");
    printf("\t[-opr private key file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle (default PWAP)\n");
    printf("\t\t01 continue\n");
    printf("\t\t20 command decrypt\n");
    printf("\t\t40 response encrypt\n");
    exit(1);	
}
