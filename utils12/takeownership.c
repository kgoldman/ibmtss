/********************************************************************************/
/*										*/
/*			     	TPM 1.2 TakeOwnership				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: takeownership.c 1294 2018-08-09 19:08:34Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tpmstructures12.h>

TPM_RC readPubek(TSS_CONTEXT	*tssContext,
		 ReadPubek_Out	*readPubekOut,
		 ReadPubek_In	*readPubekIn);

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    TakeOwnership_In		in;
    TakeOwnership_Out		out;
    ReadPubek_In		readPubekIn;
    ReadPubek_Out		readPubekOut;
    const char			*ownerPassword = NULL; 
    const char			*srkPassword = NULL; 
    TPMT_HA 			ownerAuth;
    TPMT_HA 			srkAuth;
    unsigned char 		earr[3] = {0x01, 0x00, 0x01}; /* public exponent */
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
     
#if 0
    RSA *rsa = NULL;       	/* OpenSSL format Public Key */
    FILE *keyfile;    	/* output file for public key */
    EVP_PKEY *pkey = NULL;  /* OpenSSL public key */
    int i;
    unsigned char future_hash[TPM_HASH_SIZE];	/* hash argument in binary */

#endif
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwds") == 0) {
	    i++;
	    if (i < argc) {
		srkPassword = argv[i];
	    }
	    else {
		printf("-pwds option needs a value\n");
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
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (rc == 0) {
	if (ownerPassword == NULL) {
	    memset((uint8_t *)&ownerAuth.digest, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    ownerAuth.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&ownerAuth,
				   strlen(ownerPassword), ownerPassword,
				   0, NULL);
	}
    }
    if (rc == 0) {
	if (srkPassword == NULL) {
	    memset((uint8_t *)&srkAuth.digest, 0, SHA1_DIGEST_SIZE);
	}
	else {
	    srkAuth.hashAlg = TPM_ALG_SHA1; 
	    rc = TSS_Hash_Generate(&srkAuth,
				   strlen(srkPassword), srkPassword,
				   0, NULL);
	}
    }
    if (rc == 0) {
	in.protocolID = TPM_PID_OWNER;
	in.srkParams.keyUsage = TPM_KEY_STORAGE;
	in.srkParams.keyFlags = 0;
	in.srkParams.authDataUsage = TPM_AUTH_ALWAYS;
	in.srkParams.algorithmParms.algorithmID = TPM_ALG_RSA;  
	in.srkParams.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1; 
	in.srkParams.algorithmParms.sigScheme = TPM_ES_NONE;
	in.srkParams.algorithmParms.parms.rsaParms.keyLength = 2048;  
	in.srkParams.algorithmParms.parms.rsaParms.numPrimes = 2;  
	in.srkParams.algorithmParms.parms.rsaParms.exponentSize = 0;  
	in.srkParams.PCRInfo.localityAtCreation = TPM_LOC_ZERO;
	in.srkParams.PCRInfo.localityAtRelease = TPM_LOC_ALL;
	in.srkParams.PCRInfo.creationPCRSelection.sizeOfSelect = 3;
	memset(in.srkParams.PCRInfo.creationPCRSelection.pcrSelect, 0, 3);
	in.srkParams.PCRInfo.releasePCRSelection.sizeOfSelect = 3;
	memset(in.srkParams.PCRInfo.releasePCRSelection.pcrSelect, 0, 3);
	memset(in.srkParams.PCRInfo.digestAtCreation, 0, SHA1_DIGEST_SIZE);
	memset(in.srkParams.PCRInfo.digestAtRelease, 0, SHA1_DIGEST_SIZE);
	in.srkParams.pubKey.keyLength = 0;   
	in.srkParams.encData.keyLength = 0;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /*
      encrypt the authorizations with the EK
     */
    /* read the EK public key */
    if (rc == 0) {
	rc = readPubek(tssContext,
		       &readPubekOut,
		       &readPubekIn);
	if (verbose) TSS_PrintAll("EK public key",
				  readPubekOut.pubEndorsementKey.pubKey.key,
				  readPubekOut.pubEndorsementKey.pubKey.keyLength);

    }
    /* encrypt the owner Auth */
    if (rc == 0) {
	if (verbose) TSS_PrintAll("Owner Auth",
				  (uint8_t *)&ownerAuth.digest,
				  SHA1_DIGEST_SIZE);

	in.encOwnerAuthSize = 256;
	rc = TSS_RSAPublicEncrypt((uint8_t *)&in.encOwnerAuth,	/* encrypted data */
				  /* size of encrypted data buffer */
				  readPubekOut.pubEndorsementKey.pubKey.keyLength,   
				  (uint8_t *)&ownerAuth.digest, /* decrypted data */
				  SHA1_DIGEST_SIZE,
				  readPubekOut.pubEndorsementKey.pubKey.key,	/* pub modulus */
				  readPubekOut.pubEndorsementKey.pubKey.keyLength,
				  earr, 			/* public exponent */
				  sizeof(earr),
				  (unsigned char *)"TCPA",	/* OAEP encoding parameter */
				  4,				/* TCPA not null perminated */
				  TPM_ALG_SHA1);
	if (verbose) TSS_PrintAll("Encrypted Owner Auth",
				  in.encOwnerAuth,
				  in.encOwnerAuthSize);

    }
    /* encrypt the SRK Auth */
    if (rc == 0) {
	in.encSrkAuthSize = 256;
	rc = TSS_RSAPublicEncrypt((uint8_t *)&in.encSrkAuth,   	/* encrypted data */
				  /* size of encrypted data buffer */
				  readPubekOut.pubEndorsementKey.pubKey.keyLength,
				  (uint8_t *)&srkAuth.digest, 	/* decrypted data */
				  SHA1_DIGEST_SIZE,
				  readPubekOut.pubEndorsementKey.pubKey.key,	/* pub modulus */
				  readPubekOut.pubEndorsementKey.pubKey.keyLength,
				  earr, 			/* public exponent */
				  sizeof(earr),
				  (unsigned char *)"TCPA",	/* OAEP encoding parameter */
				  4,				/* TCPA not null perminated */
				  TPM_ALG_SHA1);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_TakeOwnership,
			 sessionHandle0, ownerPassword, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);
	
	if (rc != 0) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("TPM_TakeOwnership: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
#if 0	/* FIXME save SRK public key */

	/* convert the returned public key to OpenSSL format and */
	/* export it to a file */
    rsa = TSS_convpubkey(&(srk.pub));
    if (rsa == NULL) {
	printf("Error from TSS_convpubkey\n");
	exit(-3);
    }
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
	printf("Unable to create EVP_PKEY\n");
	exit(-4);
    }
    ret = EVP_PKEY_assign_RSA(pkey,rsa);
    if (ret == 0) {
	printf("Unable to assign public key to EVP_PKEY\n");
	exit(-5);
    }
    keyfile = fopen("srk.pem","wb");
    if (keyfile == NULL) {
	printf("Unable to create public key file\n");
	exit(-6);
    }
    ret = PEM_write_PUBKEY(keyfile,pkey);
    if (ret == 0) {
	printf("Unable to write public key file\n");
	exit(-7);
    }
    fclose(keyfile);
    EVP_PKEY_free(pkey);
    exit(0);
#endif
    return rc;

}

TPM_RC readPubek(TSS_CONTEXT	*tssContext,
		 ReadPubek_Out	*readPubekOut,
		 ReadPubek_In	*readPubekIn)
{
    TPM_RC 	rc = 0;

    if (rc == 0) {
	memset(readPubekIn->antiReplay, 0, sizeof(readPubekIn->antiReplay));
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)readPubekOut,
			 (COMMAND_PARAMETERS *)readPubekIn,
			 NULL,
			 TPM_ORD_ReadPubek,
			 TPM_RH_NULL, NULL, 0);
	
	if (rc != 0) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("TPM_ReadPubek: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("takeownership\n");
    printf("\n");
    printf("Runs TPM_TakeOwnership\n");
    printf("\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t[-pwds SRK password (default zeros)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    exit(1);
}
