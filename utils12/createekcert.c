/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client EK and EK certificate  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: createekcert.c 1287 2018-07-30 13:34:27Z kgoldman $		*/
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

/* This program provisions an EK certificate.  It is required only for a SW TPM, which does not, of
   course, come with a certificate.

   Prerequisites - FIXME in the future, merge these into this program
   -------------

   ownerreadinternalpub to read the EK public key to a file

   createendorsementkeypair to create the EK.
   
   nvdefinespace to create NV Index.

   Steps implemented
   -----------------

   Read the EK public key

   Create a certificate using the CA key cakey.pem

   Write the certificate to NV.  Assumes the nv index has been defined and is of sufficient size.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "openssl/pem.h"

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal12_fp.h>
#include "ekutils.h"
#include "ekutils12.h"

/* local function prototypes */

static void printUsage(void);

static TPM_RC storeEkCertificate(TSS_CONTEXT *tssContext,
				 const char *ownerPassword,
				 TPM_AUTHHANDLE sessionHandle,
				 uint32_t certLength,
				 unsigned char *certificate,	
				 TPMI_RH_NV_INDEX nvIndex);
static TPM_RC startOIAP(TSS_CONTEXT *tssContext,
			TPM_AUTHHANDLE *sessionHandle);
static TPM_RC flushSpecific(TSS_CONTEXT *tssContext,
			    TPM_AUTHHANDLE sessionHandle);

int vverbose = 0;
int verbose = 0;

int main(int argc, char *argv[])
{
    int 		rc = 0;
    int			i;    /* argc iterator */
    TSS_CONTEXT 	*tssContext = NULL;
    const char		*certificateFilename = NULL;
    TPMI_RH_NV_INDEX	ekCertIndex = TPM_NV_INDEX_EKCert;
    const char 		*ekPubkeyFilename = NULL;
    /* the CA for endorsement key certificates */
    const char 		*caKeyFileName = NULL;
    const char 		*caKeyPassword = "";
    const char		*ownerPassword = NULL; 

    /* FIXME may be better from command line or config file */
    char *subjectEntries[] = {
	"US",		/* 0 country */
	"NY",		/* 1 state */
	"Yorktown",	/* 2 locality*/
	"IBM",		/* 3 organization */
	NULL,		/* 4 organization unit */
	"IBM SW TPM",	/* 5 common name */
	NULL		/* 6 email */
    };
    /* FIXME should come from root certificate, cacert.pem, cacertec.pem */
    char *rootIssuerEntriesRsa[] = {
	"US"			,
	"NY"			,
	"Yorktown"		,
	"IBM"			,
	NULL			,
	"EK CA"			,
	NULL	
    };
    /* only RSA for TPM 1.2 */
    char 		**issuerEntries = rootIssuerEntriesRsa;
    size_t		issuerEntriesSize = sizeof(rootIssuerEntriesRsa)/sizeof(char *);

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		certificateFilename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cakey") == 0) {
	    i++;
	    if (i < argc) {
		caKeyFileName = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -cakey\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-capwd") == 0) {
	    i++;
	    if (i < argc) {
		caKeyPassword = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -capwd\n");
		printUsage();
	    }
	}
	else if (!strcmp("-iek",argv[i])) {
	    i++;
	    if (i < argc) {
		ekPubkeyFilename = argv[i];
	    } else {
		printf("Missing parameter for -iek\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = 1;
	}
	else if (strcmp(argv[i],"-vv") == 0) {
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");	/* trace entire TSS */
	    verbose = 1;
	    vverbose = 1;
	}
	else {
 	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (caKeyFileName == NULL) {
	printf("ERROR: Missing -cakey\n");
	printUsage();
    }
    if (ekPubkeyFilename == NULL) {
	printf("\nMissing -iek argument\n");
	printUsage();
    }
   /* Precalculate the openssl nids, into global table */
    if (rc == 0) {
	rc = calculateNid();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* read the EK TPM_PUBKEY */
    TPM_PUBKEY 	ekPubkey;			/* TPM_PUBKEY EK */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&ekPubkey,
				    (UnmarshalFunction_t)TSS_TPM_PUBKEY_Unmarshalu,
				    ekPubkeyFilename);
    }
    TPMT_PUBLIC 	tpmtPublicOut;		/* primary key public part */
    /* construct the TPMT_PUBLIC from the EK public key */
    if (rc == 0) {
	tpmtPublicOut.type = TPM_ALG_RSA;
	tpmtPublicOut.nameAlg = TPM_ALG_SHA1;
	tpmtPublicOut.objectAttributes.val = TPMA_OBJECT_DECRYPT;
	tpmtPublicOut.authPolicy.t.size = 0;
	tpmtPublicOut.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;	
	tpmtPublicOut.parameters.rsaDetail.symmetric.keyBits.aes = 128;	
	tpmtPublicOut.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;	
	tpmtPublicOut.parameters.rsaDetail.keyBits = 2048;	
	tpmtPublicOut.parameters.rsaDetail.exponent = 0;
	tpmtPublicOut.unique.rsa.t.size = ekPubkey.pubKey.keyLength;
	/* FIXME range check */
	memcpy(tpmtPublicOut.unique.rsa.t.buffer, ekPubkey.pubKey.key, ekPubkey.pubKey.keyLength);
    }
    /* create the EK certificate from the EK public key, using the above issuer and subject */
    char *x509CertString = NULL;
    char *pemCertString = NULL;
    uint32_t certLength;
    unsigned char *certificate = NULL;
    if (rc == 0) {
	rc = createCertificate(&x509CertString,			/* freed @3 */
			       &pemCertString,			/* freed @2 */
			       &certLength,
			       &certificate,			/* output, freed @1 */
			       &tpmtPublicOut,			/* public key to be certified */
			       caKeyFileName,			/* CA signing key */
			       issuerEntriesSize,
			       issuerEntries,			/* certificate issuer */
			       sizeof(subjectEntries)/sizeof(char *),
			       subjectEntries,			/* certificate subject */
			       caKeyPassword);			/* CA signing key password */
    }
    /* start an OIAP session */
    TPM_AUTHHANDLE sessionHandle;
    if (rc == 0) {
	rc = startOIAP(tssContext,
		       &sessionHandle);
	if (verbose) printf("createekcert: startOIAP %08x\n", sessionHandle);
    }
    /* store the EK certificate in NV */
    if (rc == 0) {
	rc = storeEkCertificate(tssContext,
				ownerPassword,
				sessionHandle,
				certLength, certificate,	
				ekCertIndex);
    }
    /* flush the OIAP session */
    if (rc == 0) {
	if (verbose) printf("createekcert: flushSpecific %08x\n", sessionHandle);
	rc = flushSpecific(tssContext,
			   sessionHandle);
    }
    /* optionally store the certificate in DER format */
    if ((rc == 0) && (certificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(certificate, certLength, certificateFilename);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    free(certificate);			/* @1 */
    free(pemCertString);		/* @2 */
    free(x509CertString);		/* @3 */
    return rc;
}

/* storeEkCertificate() writes the EK certificate at the specified NV index.  It does not define the
   NV index.  */

static TPM_RC storeEkCertificate(TSS_CONTEXT *tssContext,
				 const char *ownerPassword,
				 TPM_AUTHHANDLE sessionHandle,
				 uint32_t certLength,
				 unsigned char *certificate,	
				 TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 			rc = 0;
    NV_WriteValue_In 		nvWriteIn;
    uint32_t 			nvBufferMax;		/* max write in one chunk */
    uint32_t			certWritten = 0;
    int				done = FALSE;

    if (rc == 0) {
	rc = readNvBufferMax12(tssContext,
			       &nvBufferMax);
    }    
    if (rc == 0) {
	if (verbose) printf("storeEkCertificate: certificate %u bytes to %08x\n",
			    certLength, nvIndex);
	nvWriteIn.nvIndex = nvIndex;
	nvWriteIn.offset = 0;		/* offset is bytes written so far */
    }
    /* store the TPM 1.2 certificate header.  See the PC Client Implementation spec 1.21 Table 9 */
    if (rc == 0) {
	uint8_t *buffer = nvWriteIn.data+3;
	uint16_t written = 0;
	uint16_t certLength16 = certLength + 2;	/* add two bytes for the TCG_FULL_CERT tag */
	nvWriteIn.data[0] = 0x10;		/* TCG_TAG_PCCLIENT_STORED_CERT	1001h */
	nvWriteIn.data[1] = 0x01;
	nvWriteIn.data[2] = 0x00;		/* TCG_FULL_CERT	0 */
	nvWriteIn.data[5] = 0x10;		/* TCG_TAG_PCCLIENT_FULL_CERT	1002h */
	nvWriteIn.data[6] = 0x02;
	TSS_UINT16_Marshalu(&certLength16, &written, &buffer, NULL);
	nvWriteIn.dataSize = 7;
	if (verbose) printf("storeEkCertificate: writing header %u bytes at offset %u to %08x\n",
			    nvWriteIn.dataSize, nvWriteIn.offset, nvIndex);
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&nvWriteIn,
			 NULL,
			 TPM_ORD_NV_WriteValue,
			 sessionHandle, ownerPassword, 1,
			 TPM_RH_NULL, NULL, 0);
	nvWriteIn.offset += nvWriteIn.dataSize;
    }
    while ((rc == 0) && !done) {
	if (rc == 0) {
	    /* calculate bytes to write in this pass */
	    if ((certLength - certWritten) < nvBufferMax) {
		nvWriteIn.dataSize = certLength - certWritten;	/* last chunk */
	    }
	    else {
		nvWriteIn.dataSize = nvBufferMax;		/* next chunk */
	    }
	    memcpy(nvWriteIn.data, certificate + certWritten, nvWriteIn.dataSize);
	}
	if (rc == 0) {
	    if (verbose) printf("storeEkCertificate: "
				"writing certificate %u bytes at offset %u to %08x\n",
				nvWriteIn.dataSize, nvWriteIn.offset, nvIndex);
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&nvWriteIn,
			     NULL,
			     TPM_ORD_NV_WriteValue,
			     sessionHandle, ownerPassword, 1,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    nvWriteIn.offset += nvWriteIn.dataSize;
	    certWritten += nvWriteIn.dataSize;
	    if (certWritten == certLength) {
		done = TRUE;
	    }
	}
    }
    if (rc == 0) {
	if (verbose) printf("storeEkCertificate: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("storeEkCertificate: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC startOIAP(TSS_CONTEXT *tssContext,
		 TPM_AUTHHANDLE *sessionHandle)
{
    TPM_RC 			rc = 0;
    OIAP_Out 			out;
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 NULL,
			 NULL,
			 TPM_ORD_OIAP,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (verbose) printf("startOIAP: Handle %08x\n", out.authHandle);
	*sessionHandle = out.authHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("oiap: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static TPM_RC flushSpecific(TSS_CONTEXT *tssContext,
			    TPM_AUTHHANDLE sessionHandle)
{
    TPM_RC			rc = 0;
    FlushSpecific_In 		in;
    if (rc == 0) {
	in.handle = sessionHandle;
	in.resourceType = TPM_RT_AUTH;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_FlushSpecific,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (verbose) printf("flushspecific: handle %08x success\n",
			    sessionHandle);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("flushspecific: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createekcert\n");
    printf("\n");
    printf("Provisions an EK certificate\n");
    printf("E.g.,\n");
    printf("\n");
    printf("createekcert -cakey cakey.pem -capwd rrrr -ip ekpub.bin\n");
    printf("\n");
    printf("\t[-pwdo owner password (default zeros)]\n");
    printf("\t-iek TPM_PUBKEY EK file name\n");
    printf("\t-cakey CA PEM key file name\n");
    printf("\t[-capwd CA PEM key password (default empty)]\n");
    printf("\t[-of - DER certificate output file name]\n");
    printf("\n");
    printf("Currently:\n");
    printf("\n");
    printf("\tCertificate issuer, subject, and validity are hard coded.\n");
    exit(1);	
}
