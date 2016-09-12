/********************************************************************************/
/*										*/
/*			   Load External					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadexternal.c 686 2016-07-20 16:30:54Z kgoldman $		*/
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
#include <tss2/tssprint.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

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

/* loadExternalTPM() loads a key pair saved in TPM format

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
    TPM_RC			rc = 0;
    RSA 			*rsakey = NULL;
    unsigned char		*derBuffer = NULL;
    size_t			derSize;
    int         bytes;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     /* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;
	d2i_RSAPrivateKey(&rsakey, &tmpPtr, derSize);		/* freed @2 */
    }    
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	in->inPublic.t.publicArea.type = TPM_ALG_RSA;
	in->inPublic.t.publicArea.nameAlg = nalg;
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_SIGN;
	}
	else {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_DECRYPT;
	}
	in->inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	in->inPublic.t.publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */
	in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */
	/* the scheme openssl uses on the command line? */
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	}
	else {
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	}
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	in->inPublic.t.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	in->inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;	
	in->inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
	/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */
    }
    /* get the public modulus */
    /* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
    if (rc == 0) {
	bytes = BN_num_bytes(rsakey->n);
	if (bytes > MAX_RSA_KEY_BYTES) {
	    printf("Error, public key modulus %d greater than %u\n", bytes, MAX_RSA_KEY_BYTES);
	    rc = EXIT_FAILURE;
	}
	else {
	    in->inPublic.t.publicArea.unique.rsa.t.size =
		BN_bn2bin(rsakey->n,
			  (uint8_t *)&in->inPublic.t.publicArea.unique.rsa.t.buffer);
	}
    }
    if (rc == 0) {
	in->inPrivate.t.size = 1;		/* true means optional parameter present, flag for
						   marshaler */
	in->inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_RSA;
	in->inPrivate.t.sensitiveArea.authValue.t.size = 0;
	in->inPrivate.t.sensitiveArea.seedValue.t.size = 0;
    }
    /* get a prime factor */
    if (rc == 0) {
	bytes = BN_num_bytes(rsakey->p);
	if (bytes > MAX_RSA_KEY_BYTES/2) {
	    printf("Error, private prime p %d greater than %u\n", bytes, MAX_RSA_KEY_BYTES/2);
	    rc = EXIT_FAILURE;
	}
	else {
	    in->inPrivate.t.sensitiveArea.sensitive.rsa.t.size =
		BN_bn2bin(rsakey->p,
			  (uint8_t *)&in->inPrivate.t.sensitiveArea.sensitive.rsa.t.buffer);
	}
    }
    free(derBuffer);			/* @1 */
    if (rsakey != NULL) {
	RSA_free(rsakey);		/* @2 */
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
    TPM_RC			rc = 0;
    FILE 			*pemKeyFile = NULL;
    EVP_PKEY 			*pemKeyEvp = NULL;
    RSA 			*rsaPubkey = NULL;

    /* open the pem format file */
    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    /* convert the file to an EVP public key */
    if (rc == 0) {
	pemKeyEvp = PEM_read_PUBKEY(pemKeyFile, NULL, NULL, NULL);
	if (pemKeyEvp == NULL) {
	    printf("Error PEM_read_PUBKEY reading public key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    /* convert to openssl key token */
    if (rc == 0) {
	rsaPubkey = EVP_PKEY_get1_RSA(pemKeyEvp);	/* freed @1 */
	if (rsaPubkey == NULL) {
	    printf("Error: EVP_PKEY_get1_RSA converting public key\n");
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	in->inPublic.t.publicArea.type = TPM_ALG_RSA;
	in->inPublic.t.publicArea.nameAlg = nalg;
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_SIGN;
	}
	else {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_DECRYPT;
	}
	in->inPublic.t.publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */
	in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	}
	else {
	    in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	}
	/* or always use RSASSA (sample code) */
	in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	in->inPublic.t.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	in->inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;	
	in->inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
	/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */
    }
    /* get the public modulus */
    /* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
    if (rc == 0) {
	int         bytes;
	bytes = BN_num_bytes(rsaPubkey->n);
	if (bytes > MAX_RSA_KEY_BYTES) {
	    printf("Error, public key modulus %d greater than %u\n", bytes, MAX_RSA_KEY_BYTES);
	    rc = EXIT_FAILURE;
	}
	else {
	    in->inPublic.t.publicArea.unique.rsa.t.size =
		BN_bn2bin(rsaPubkey->n,
			  (uint8_t *)&in->inPublic.t.publicArea.unique.rsa.t.buffer);
	}
    }
    if (rc == 0) {
	in->inPrivate.t.size = 0;
    }
    if (rsaPubkey != NULL) {
	RSA_free(rsaPubkey);			/* @1 */
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
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
    TPM_RC			rc = 0;
    FILE 			*pemKeyFile = NULL;
    EVP_PKEY 			*pemKeyEvp = NULL;
    EC_KEY 			*ecKey = NULL;
    const EC_POINT 		*ecPoint;
    const EC_GROUP 		*ecGroup;
    uint8_t 			*modulusBin = NULL;
    int 			modulusBytes;

    /* open the pem format file */
    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    /* convert the file to an EVP public key */
    if (rc == 0) {
	pemKeyEvp = PEM_read_PUBKEY(pemKeyFile, NULL, NULL, NULL);
	if (pemKeyEvp == NULL) {
	    printf("Error PEM_read_PUBKEY reading public key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	if (pemKeyEvp->type != EVP_PKEY_EC) {
	    printf("PEM Public key is not EC\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    /* convert the public key to openssl structure */
    if (rc == 0) {
	ecKey = EVP_PKEY_get1_EC_KEY(pemKeyEvp);		/* freed @3 */
	if (ecKey == NULL) {
	    printf("Could not extract EC public key from X509 certificate\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    if (rc == 0) {
	ecPoint = EC_KEY_get0_public_key(ecKey);
	if (ecPoint == NULL) {
	    printf("Could not extract EC point from EC public key\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    if (rc == 0) {   
	ecGroup = EC_KEY_get0_group(ecKey);
	if (ecGroup  == NULL) {
	    printf("Could not extract EC group from EC public key\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }

    /* get the public modulus */
    if (rc == 0) {   
	modulusBytes = EC_POINT_point2oct(ecGroup, ecPoint,
					  POINT_CONVERSION_UNCOMPRESSED,
					  NULL, 0, NULL);
	if (modulusBytes != 65) {	/* 1 for compression + 32 + 32 */
	    printf("Public modulus expected 65 bytes, actual %u\n", modulusBytes);
	    rc = TPM_RC_INTEGRITY;
	}	    
    }
    if (rc == 0) {   
	modulusBin = malloc(modulusBytes);	/* freed @3 */
	if (modulusBin == NULL) {
	    printf("Error allocating %u bytes for modulusBin\n", modulusBytes);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	EC_POINT_point2oct(ecGroup, ecPoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   modulusBin, modulusBytes, NULL);
	if (verbose) TSS_PrintAll("ECC public key:", modulusBin, modulusBytes);
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	in->inPublic.t.publicArea.type = TPM_ALG_ECC;
	in->inPublic.t.publicArea.nameAlg = nalg;
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_SIGN;
	}
	else {
	    in->inPublic.t.publicArea.objectAttributes.val = TPMA_OBJECT_DECRYPT;
	}
	in->inPublic.t.publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	in->inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	if (keyType == TYPE_SI) {
	    in->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	}
	else {
	    in->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	}
	/* or always use ECDS (sample code) */
	in->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	in->inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
	in->inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;	
	in->inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	in->inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
    }
    if (rc == 0) {
	in->inPublic.t.publicArea.unique.ecc.x.t.size = 32;	
	memcpy(in->inPublic.t.publicArea.unique.ecc.x.t.buffer, modulusBin +1, 32);	

	in->inPublic.t.publicArea.unique.ecc.y.t.size = 32;	
	memcpy(in->inPublic.t.publicArea.unique.ecc.y.t.buffer, modulusBin +33, 32);	
    }
    if (rc == 0) {
	in->inPrivate.t.size = 0;
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    free(modulusBin);				/* @3 */
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
