/********************************************************************************/
/*										*/
/*			    Sign Application					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: signapp.c 682 2016-07-15 18:49:19Z kgoldman $		*/
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
   This does a multiple step application.  It is used to test session state encryption.  Encryption
   does not work in a single step per process model, since a new AES key is generated each time the
   TSS is started.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsscrypto.h>
#include <tss2/Unmarshal_fp.h>


static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    char 			hierarchyChar = 'n';
    TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_NULL;
    CreatePrimary_In 		createPrimaryIn;
    CreatePrimary_Out 		createPrimaryOut;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    Create_In 			createIn;
    Create_Out 			createOut;
    Load_In 			loadIn;
    Load_Out 			loadOut;
    Sign_In 			signIn;
    Sign_Out 			signOut;
    VerifySignature_In 		verifySignatureIn;
    VerifySignature_Out 	verifySignatureOut;
    FlushContext_In 		flushContextIn;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    uint32_t           		sizeInBytes;	/* hash algorithm mapped to size */           		
    const char			*messageFilename = NULL;
    unsigned char 		*message = NULL;	/* message */
    size_t 			messageLength;
    TPMT_HA 			digest;		/* digest of the message */
    const char			*primaryPassword = NULL; 
    const char			*keyPassword = NULL; 

    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
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
		primaryPassword = argv[i];
	    }
	    else {
		printf("-pwdp option needs a value\n");
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
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		messageFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
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
    if (messageFilename == NULL) {
	printf("Missing message file name -if\n");
	printUsage();
    }
    /* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
    if (rc == 0) {
	if (hierarchyChar == 'e') {
	    primaryHandle = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    primaryHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    primaryHandle = TPM_RH_PLATFORM;
	}
	else if (hierarchyChar == 'n') {
	    primaryHandle = TPM_RH_NULL;
	}
	else {
	    printf("Bad parameter %c for -hi\n", hierarchyChar);
	    printUsage();
	}
    }
    /* get message to be signed */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&message,     /* must be freed by caller */
				     &messageLength,
				     messageFilename);
    }
    /* hash the message file */
    if (rc == 0) {
	digest.hashAlg = halg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	rc = TSS_Hash_Generate(&digest,
			       messageLength, message,
			       0, NULL);
    }
    /*
      Start a TSS context
    */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /*
      Start an authorization session
    */
    if (rc == 0) {
	startAuthSessionIn.sessionType = TPM_SE_HMAC;
	startAuthSessionIn.tpmKey = TPM_RH_NULL;
	startAuthSessionIn.encryptedSalt.b.size = 0;
	startAuthSessionIn.bind = TPM_RH_NULL;
	startAuthSessionIn.nonceCaller.t.size = 0;
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
	startAuthSessionIn.symmetric.keyBits.xorr = halg;
	startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
	startAuthSessionIn.authHash = halg;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 NULL,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Create the primary storage key
    */
    if (rc == 0) {
	createPrimaryIn.primaryHandle = primaryHandle;
	createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
   }
    if (rc == 0) {
	if (primaryPassword == NULL) {
	    createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&createPrimaryIn.inSensitive.t.sensitive.userAuth.b,
				      primaryPassword, sizeof(TPMU_HA));
	}
    }
    if (rc == 0) {
	createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
	createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
	createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
	createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.size = 0;
	createPrimaryIn.outsideInfo.t.size = 0;
	createPrimaryIn.creationPCR.count = 0;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Create the signing key
    */
    if (rc == 0) {
	createIn.parentHandle = createPrimaryOut.objectHandle;
    }
    if (rc == 0) {
	if (keyPassword == NULL) {
	    createIn.inSensitive.t.sensitive.userAuth.t.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&createIn.inSensitive.t.sensitive.userAuth.b,
				      keyPassword, sizeof(TPMU_HA));
	}
    }
    if (rc == 0) {
	createIn.inSensitive.t.sensitive.data.t.size = 0;
	createIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* default empty policy */
	createIn.inPublic.t.publicArea.nameAlg = halg;
	createIn.inPublic.t.publicArea.objectAttributes.val = 0;
	createIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
	createIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	createIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	createIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	createIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	createIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	createIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	createIn.inPublic.t.publicArea.type = TPM_ALG_RSA;		/* for the RSA template */
	createIn.inPublic.t.publicArea.nameAlg = halg;
	createIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	createIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	createIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
	createIn.inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
	createIn.inPublic.t.publicArea.unique.rsa.t.size = 0;
	createIn.outsideInfo.t.size = 0;
	createIn.creationPCR.count = 0;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createOut,
			 (COMMAND_PARAMETERS *)&createIn,
			 NULL,
			 TPM_CC_Create,
			 startAuthSessionOut.sessionHandle, primaryPassword, 1,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Load the signing key
    */
    if (rc == 0) {
	loadIn.parentHandle = createPrimaryOut.objectHandle;
	loadIn.inPrivate = createOut.outPrivate;
	loadIn.inPublic = createOut.outPublic;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&loadOut,
			 (COMMAND_PARAMETERS *)&loadIn,
			 NULL,
			 TPM_CC_Load,
			 startAuthSessionOut.sessionHandle, primaryPassword, 1,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Sign
    */
    if (rc == 0) {
	signIn.keyHandle = loadOut.objectHandle;
	signIn.digest.t.size = sizeInBytes;
	memcpy(&signIn.digest.t.buffer, (uint8_t *)&digest.digest, sizeInBytes);
	signIn.inScheme.scheme = TPM_ALG_RSASSA;
	signIn.inScheme.details.rsassa.hashAlg = halg;
	signIn.validation.tag = TPM_ST_HASHCHECK;
	signIn.validation.hierarchy = TPM_RH_NULL;
	signIn.validation.digest.t.size = 0;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&signOut,
			 (COMMAND_PARAMETERS *)&signIn,
			 NULL,
			 TPM_CC_Sign,
			 startAuthSessionOut.sessionHandle, keyPassword, 1,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Verify the signature
    */
    if (rc == 0) {
	verifySignatureIn.keyHandle = signIn.keyHandle;
	verifySignatureIn.digest.t.size = sizeInBytes;
	memcpy(&verifySignatureIn.digest.t.buffer, (uint8_t *)&digest.digest, sizeInBytes);
	verifySignatureIn.signature = signOut.signature;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&verifySignatureOut,
			 (COMMAND_PARAMETERS *)&verifySignatureIn,
			 NULL,
			 TPM_CC_VerifySignature,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Flush the primary key
    */
    if (rc == 0) {
	flushContextIn.flushHandle = createPrimaryOut.objectHandle;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Flush the signing key
    */
    if (rc == 0) {
	flushContextIn.flushHandle = signIn.keyHandle;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    /*
      Flush the session
    */
    if (rc == 0) {
	flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    {  
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("signapp: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("signapp: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(message);
    return rc;
}
    
static void printUsage(void)
{
    printf("\n");
    printf("signapp\n");
    printf("\n");
    printf("Runs TPM2_Sign application, including creating and loading a primary storage key\n");
    printf("and primary key\n");
    printf("\n");
    printf("\t[-hi hierarchy e, o, p, n (default null)]\n");
    printf("\t[-pwdp password for primary key (default empty)]\n");
    printf("\t[-pwdk password for signing key (default empty)]\n");
    printf("\t[-halg [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t-if input message to hash and sign\n");
    printf("\n");
    exit(1);	
}
