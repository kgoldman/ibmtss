/********************************************************************************/
/*										*/
/*			    NV Write		 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nvwrite.c 682 2016-07-15 18:49:19Z kgoldman $		*/
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

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>

static TPM_RC readNvBufferMax(uint32_t *nvBufferMax,
			      TSS_CONTEXT *tssContext);
static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_Write_In 		in;
    uint16_t 			offset = 0;			/* default 0 */
    uint32_t 			pinPass;
    uint32_t 			pinLimit;
    int				inData = FALSE;
    unsigned int		dataSource = 0;
    const char 			*data = NULL;
    const char 			*datafilename = NULL;
    char 			hierarchyAuthChar = 0;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    const char			*nvPassword = NULL; 		/* default no password */
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    uint32_t 			nvBufferMax;
    unsigned char 		*writeBuffer = NULL; 
    uint16_t 			written;			/* bytes written so far */
    int				done = FALSE;
 
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hia") == 0) {
	    i++;
	    if (i < argc) {
		hierarchyAuthChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hia\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		data = argv[i];
		dataSource++;
	    }
	    else {
		printf("-ic option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-if")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
		dataSource++;
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-id")  == 0) {
	    i++;
	    if (i < argc) {
		pinPass = atoi(argv[i]);
	    }
	    i++;
	    if (i < argc) {
		pinLimit = atoi(argv[i]);
		dataSource++;
		inData = TRUE;
	    }
	    else {
		printf("-id option needs two values\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-off") == 0) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
		/* FIXME range check */
	    }
	    else {
		printf("-off option needs a value\n");
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
    if ((nvIndex >> 24) != TPM_HT_NV_INDEX) {
	printf("NV index handle not specified or out of range, MSB not 01\n");
	printUsage();
    }
    if (dataSource > 1) {
	printf("More than one input data source (-if, -ic, -id\n");
	printUsage();
    }
    /* Authorization handle */
    if (rc == 0) {
	if (hierarchyAuthChar == 'o') {
	    in.authHandle = TPM_RH_OWNER;  
	}
	else if (hierarchyAuthChar == 'p') {
	    in.authHandle = TPM_RH_PLATFORM;  
	}
	else if (hierarchyAuthChar == 0) {
	    in.authHandle = nvIndex;
	}
	else {
	    printf("\n");
	    printUsage();
	}
    }
    /* if there is no input data source, default to 0 byte write */
    if (dataSource == 0) {
	in.data.b.size = 0;
    }
    /* command line data must fit in one write */
    if (data != NULL) {
	rc = TSS_TPM2B_StringCopy(&in.data.b,
				  data, MAX_NV_BUFFER_SIZE);
	
    }
    /* file data can be written in chunks */
    size_t writeLength;		/* total bytes to write */
    if (datafilename != NULL) {
	written = 0;
	rc = TSS_File_ReadBinaryFile(&writeBuffer,     /* freed @1 */
				     &writeLength,
				     datafilename);
    }
    if (inData) {
	in.data.b.size = sizeof(uint32_t) + sizeof(uint32_t);
	*(uint32_t *)(in.data.b.buffer) = htonl(pinPass);
	*((uint32_t *)(in.data.b.buffer) + 1) = htonl(pinLimit);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* If data comes from a file, it may have to be written in chunks.  Read the
       TPM_PT_NV_BUFFER_MAX, the chunk size */
    if ((rc == 0) && (datafilename != NULL)) {
	rc = readNvBufferMax(&nvBufferMax,
			     tssContext);
    }    
    if (rc == 0) {
	in.nvIndex = nvIndex;
	in.offset = offset;
    }
    while ((rc == 0) && !done) {
	uint16_t writeBytes;		/* bytes to write in this pass */
	if (rc == 0) {
	    /* write a chunk */
	    if (datafilename != NULL) {
		in.offset += written;
		if ((writeLength - written) < nvBufferMax) {
		    writeBytes = writeLength - written;	/* last chunk */
		}
		else {
		    writeBytes = nvBufferMax;	/* next chunk */
		}
		rc = TSS_TPM2B_Create(&in.data.b, writeBuffer + written, writeBytes, MAX_NV_BUFFER_SIZE);
	    }
	}
	/* call TSS to execute the command */
	if (rc == 0) {
	    if (verbose) printf("nvwrite: writing %u bytes\n", in.data.b.size);
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_Write,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	/* data file can be written in chunks, other options are single write */
	if (rc == 0) {
	    if (datafilename == NULL) {
		done = TRUE;
	    }
	    else {
		written += writeBytes;
		if (written == writeLength) {
		    done = TRUE;
		}
	    }
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("nvwrite: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvwrite: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	if (rc == TSS_RC_FILE_OPEN) {
	    printf("Possible cause: missing nvreadpublic before nvwrite\n");
	}
	rc = EXIT_FAILURE;
    }
    free(writeBuffer);	/* @1 */
    return rc;
}

TPM_RC readNvBufferMax(uint32_t *nvBufferMax,
		       TSS_CONTEXT *tssContext)
{
    TPM_RC			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;

    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_NV_BUFFER_MAX;
    in.propertyCount = 1;	/* ask for one property */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    /* sanity check that the property name is correct, demo of how to parse the structure */
    if (rc == 0) {
	if (out.capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_NV_BUFFER_MAX) {
	    *nvBufferMax = out.capabilityData.data.tpmProperties.tpmProperty[0].value;
	    if (verbose) printf("readNvBufferMax: %u\n", *nvBufferMax);
	}
	else {
	    printf("readNvBufferMax: wrong property returned: %08x\n",
		   out.capabilityData.data.tpmProperties.tpmProperty[0].property);
	    *nvBufferMax = 512;
	}
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("getcapability: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvwrite\n");
    printf("\n");
    printf("Runs TPM2_NV_Write\n");
    printf("\n");
    printf("\t[-hia hierarchy authorization (o, p)(default index authorization)]\n");
    printf("\t-ha NV index handle\n");
    printf("\t-pwdn password for NV index (default empty)\n");
    printf("\t-ic data string\n");
    printf("\t-if data file\n");
    printf("\t-id data values, pinPass and pinLimit\n");
    printf("\t\tif none is specified, a 0 byte write occurs\n");
    printf("\t\t-id is normally used for pin pass or pin fail indexes\n");
    printf("\t-off offset (default 0)\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t\t01 continue\n");
    exit(1);	
}
