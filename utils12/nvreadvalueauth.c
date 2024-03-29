/********************************************************************************/
/*										*/
/*			    TPM 1.2 NV_ReadValueAuth				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2024.					*/
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

#include <openssl/x509.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tpmstructures12.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal12_fp.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_ReadValueAuth_In		in;
    NV_ReadValueAuth_Out	out;
    TPM12_NV_INDEX		nvIndex = 0xfffffffe;
    const char			*nvPassword = NULL; 
    uint16_t 			dataSize = 0;			/* bytes to read */
    int 			cert = FALSE;			/* boolean, read certificate */
    uint16_t 			offset = 0;			/* default 0 */
    const char 			*dataFilename = NULL;
    TPM_AUTHHANDLE 		sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sz") == 0) {
	    i++;
	    if (i < argc) {
		dataSize = atoi(argv[i]);
	    }
	    else {
		printf("-sz option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp("-cert",argv[i])) {
	    cert = TRUE;
	}
	else if (strcmp(argv[i],"-off") == 0) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
	    }
	    else {
		printf("-off option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of")  == 0) {
	    i++;
	    if (i < argc) {
		dataFilename = argv[i];
	    } else {
		printf("-of option needs a value\n");
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
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (nvIndex == 0xfffffffe) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (((dataSize == 0) && !cert) ||
	((dataSize != 0) && cert)) {
	printf("One of -sz or -cert must be specified!\n");
	printUsage();
    }
    if (cert && (offset != 0)) {
	printf("-off must not be specified with -cert!\n");
	printUsage();
    }
    if (dataSize > sizeof(out.data)) {
	printf("nvreadvalueauth: size %u greater than %u\n",
	       dataSize, (unsigned int)sizeof(out.data));	
	rc = TSS_RC_INSUFFICIENT_BUFFER;
    }
    /* Start a TSS context */
    if (rc == 0) {
	in.nvIndex = nvIndex;
	rc = TSS_Create(&tssContext);
    }
    if (!cert) {
	if (rc == 0) {
	    in.offset = offset;
	    in.dataSize = dataSize;
	}
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_ORD_NV_ReadValueAuth,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    TSS_PrintAll("nvreadvalueauth: data", out.data, out.dataSize);
	}
    }
    else {
	X509 *x509Certificate = NULL;
	long certSize;
	/* first read the header */
	if (rc == 0) {
	    in.offset = 0;
	    in.dataSize = 7;
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_ORD_NV_ReadValueAuth,
			     sessionHandle0, nvPassword, 1,
			     TPM_RH_NULL, NULL, 0);
	}
	/* validate the header and get the certificate length */
	if (rc == 0) {
	    TSS_PrintAll("nvreadvalueauth: header data", out.data, out.dataSize);
	    if ((out.data[0] != 0x10) ||	/* stored certificate, full certificate */
		(out.data[1] != 0x01) ||
		(out.data[2] != 0x00) ||	/* full certificate */
		(out.data[5] != 0x10) ||
		(out.data[6] != 0x02)) {
		if (tssUtilsVerbose) printf("nvreadvalueauth: certificate header error\n");
		rc = TSS_RC_X509_ERROR;
	    }
	    certSize = (out.data[3] << 8) +	/* msb */
		       out.data[4]
			       -2;		/* -2 for tag in bytes 5 and 6 */
	    
	}	
	if (rc == 0) {
	    in.offset = 7;
	    in.dataSize = certSize;
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_ORD_NV_ReadValueAuth,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     TPM_RH_NULL, NULL, 0);
	}	
	if (rc == 0) {
	    TSS_PrintAll("nvreadvalueauth: certificate", out.data, out.dataSize);
	    const uint8_t *tmpData = out.data;
	    x509Certificate = d2i_X509(NULL,	/* freed @1 */
				       (const unsigned char **)&tmpData, out.dataSize);
	    if (x509Certificate == NULL) {
		printf("nvreadvalueauth: Could not parse X509 certificate\n");
		rc = TSS_RC_X509_ERROR;
	    }
	}
	if (rc == 0) {
	    X509_print_fp(stdout, x509Certificate);
	}	
	if (x509Certificate != NULL) {
	    X509_free(x509Certificate);   	/* @1 */
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (dataFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.data, out.dataSize, dataFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("nvreadvalueauth: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvreadvalueauth: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvreadvalueauth\n");
    printf("\n");
    printf("Runs TPM_NV_ReadValueAuth\n");
    printf("\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t[-pwdn\tpassword for NV index (default zeros)]\n");
    printf("\t-sz\tdata size\n");
    printf("\t-cert\tdumps the certificate, the number of bytes is embedded in the prefix\n");
    printf("\t[-off\toffset (default 0)]\n");
    printf("\t[-of\tdata file (default do not save)]\n");
    printf("\n");
    printf("\t-se0 session handle / attributes\n");
    printf("\t\t01 continue\n");
    exit(1);
}

