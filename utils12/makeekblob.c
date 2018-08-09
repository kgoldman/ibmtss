/********************************************************************************/
/*										*/
/*			    TPM 1.2 Make EK Blob				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: makeekblob.c 1294 2018-08-09 19:08:34Z kgoldman $		*/
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tpmstructures12.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal12_fp.h>

/* This is a test program to exercise the TPM 1.2 makeidentity / activateidentity protocol.  It can
   serve as a sample program for an attestation server enrollment step */

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    const char 			*aikPubkeyFilename = NULL;
    const char 			*ekPubkeyFilename = NULL;
    const char 			*encBlobFilename = NULL;
    const char 			*symKeyFilename = NULL;
    TPM_EK_BLOB_ACTIVATE 	a1Activate;
    TPM_EK_BLOB			b1Blob;
    TPM_SYMMETRIC_KEY 		*k1SessionKey;
    unsigned char 		*aikPubkey = NULL;		/* TPM_PUBKEY AIK */
    size_t 			aikPubLength;
    TPM_PUBKEY 			ekPubkey;			/* TPM_PUBKEY EK */
    uint8_t 			decBlob[2048/8];
    size_t			decBlobLength;
    uint8_t 			encBlob[2048/8];

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i], "-iak") == 0) {
	    i++;
	    if (i < argc) {
		aikPubkeyFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -iak\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iek") == 0) {
	    i++;
	    if (i < argc) {
		ekPubkeyFilename = argv[i];
	    }
	    else {
		printf("-iek option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-ob") == 0) {
	    i++;
	    if (i < argc) {
		encBlobFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -ob\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-ok") == 0) {
	    i++;
	    if (i < argc) {
		symKeyFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -ok\n");
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
    if (aikPubkeyFilename == NULL) {
	printf("\nMissing -iak argument\n");
	printUsage();
    }
    if (ekPubkeyFilename == NULL) {
	printf("\nMissing -iek argument\n");
	printUsage();
    }
    if (encBlobFilename == NULL) {
	printf("\nMissing -ob argument\n");
	printUsage();
    }
    if (symKeyFilename == NULL) {
	printf("\nMissing -ok argument\n");
	printUsage();
    }
    if (rc == 0) {
	memset(&b1Blob, 0, sizeof(b1Blob));
	memset(&a1Activate, 0, sizeof(a1Activate));
    }
    /* create the TPM_SYMMETRIC_KEY sessionKey */
    if (rc == 0) {
	k1SessionKey = &a1Activate.sessionKey;	/* put directly in TPM_EK_BLOB_ACTIVATE */
	k1SessionKey->algId = TPM_ALG_AES128;
	k1SessionKey->encScheme = TPM_ES_SYM_CTR;
	k1SessionKey->size = sizeof(k1SessionKey->data);
	rc = TSS_RandBytes(k1SessionKey->data, k1SessionKey->size);
	if (verbose) TSS_PrintAll("makeekblob: TPM_SYMMETRIC_KEY sessionKey",
				  k1SessionKey->data, k1SessionKey->size);
    }
    /* create the TPM_EK_BLOB_ACTIVATE */
    /* read the AIK TPM_PUBKEY */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&aikPubkey,     	/* freed @1 */
				     &aikPubLength,
				     aikPubkeyFilename);
    }
    /* hash the AIK TPM_PUBKEY and copy to idDigest */
    if (rc == 0) {
	TPMT_HA pubkeyHash;
	pubkeyHash.hashAlg = TPM_ALG_SHA1; 
	rc = TSS_Hash_Generate(&pubkeyHash,
			       aikPubLength, aikPubkey,
			       0, NULL);
	memcpy(a1Activate.idDigest, (uint8_t *)&pubkeyHash.digest, SHA1_DIGEST_SIZE);
	if (verbose) TSS_PrintAll("makeekblob: TPM_EK_BLOB_ACTIVATE idDigest",
				  (uint8_t *)&pubkeyHash.digest, SHA1_DIGEST_SIZE);
    }
    if (rc == 0) {
	a1Activate.pcrInfo.pcrSelection.sizeOfSelect = 3;
	memset(a1Activate.pcrInfo.pcrSelection.pcrSelect,
	       0, a1Activate.pcrInfo.pcrSelection.sizeOfSelect);
	a1Activate.pcrInfo.localityAtRelease = TPM_LOC_ZERO;
    }
    /* create the TPM_EK_BLOB */
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = b1Blob.blob;
	uint32_t size = sizeof(b1Blob.blob);	/* max size */
	b1Blob.ekType = TPM_EK_TYPE_ACTIVATE;
	b1Blob.blobSize = 0;
	rc = TSS_TPM_EK_BLOB_ACTIVATE_Marshalu(&a1Activate, &written, &buffer, &size);
	b1Blob.blobSize = written;
    }
    /* marshal the TPM_EK_BLOB */
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = decBlob;
	uint32_t size = sizeof(decBlob);	/* max size */
	rc = TSS_TPM_EK_BLOB_Marshalu(&b1Blob, &written, &buffer, &size);
	decBlobLength = written;
    }
    if (rc == 0) {
	if (decBlobLength > sizeof(encBlob)) {
	    printf("makeekblob: TPM_EK_BLOB length %u too large\n", (unsigned int)decBlobLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the EK TPM_PUBKEY */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&ekPubkey,
				    (UnmarshalFunction_t)TSS_TPM_PUBKEY_Unmarshalu,
				    ekPubkeyFilename);
    }
    /* sanity check, should always pass for TPM 1.2 */
    if (ekPubkey.pubKey.keyLength != sizeof(encBlob)) {
	printf("makeekblob: EK length %u not equal to %u\n",
	       ekPubkey.pubKey.keyLength, (unsigned int)sizeof(encBlob));
	rc = TSS_RC_INSUFFICIENT_BUFFER;
    }
    /* encrypt the TPM_EK_BLOB */
    if (rc == 0) {
	if (verbose) TSS_PrintAll("makeekblob: TPM_EK_BLOB",
				  decBlob, decBlobLength);
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	/* encrypt the salt with the tpmKey public key */
	rc = TSS_RSAPublicEncrypt(encBlob,   		/* encrypted data */
				  sizeof(encBlob),	/* size of encrypted data buffer */
				  decBlob, 		/* decrypted data */
				  decBlobLength,
				  ekPubkey.pubKey.key,  /* public modulus */
				  ekPubkey.pubKey.keyLength,
				  earr, 		/* public exponent */
				  sizeof(earr),
				  (unsigned char *)"TCPA",	/* encoding parameter */
				  sizeof("TCPA")-1,	/* TPM 1.2 does not include NUL */
				  TPM_ALG_SHA1);	/* OAEP hash algorithm */
	if (verbose) TSS_PrintAll("makeekblob: TPM_EK_BLOB encrypted",
				  encBlob, sizeof(encBlob));
    }    
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(encBlob,
				      sizeof(encBlob),
				      encBlobFilename);
    }    
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(k1SessionKey->data,
				      k1SessionKey->size,
				      symKeyFilename);
    }    
    if (rc == 0) {
	if (verbose) printf("makeekblob: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("makeekblob: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(aikPubkey);		/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("makeekblob\n");
    printf("\n");
    printf("Calculates the encrypted blob for TPM_ActivateIdentity\n");
    printf("\n");
    printf("\t-iak AIK TPM_PUBKEY key file name\n");
    printf("\t-iek EK TPM_PUBKEY key file name\n");
    printf("\t-ob encrypted blob file name\n");
    printf("\t-ok symmetric key file name\n");
    exit(1);
}


