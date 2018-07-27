/********************************************************************************/
/*										*/
/*			TPM 1.2 EK Index Parsing Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ekutils12.c 1287 2018-07-30 13:34:27Z kgoldman $		*/
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
#include <stdint.h>
#include <limits.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/Unmarshal12_fp.h>
#include <ibmtss/tssmarshal.h>

#include "cryptoutils.h"
#include "ekutils12.h"

extern int verbose;

/* readNvBufferMax() determines the maximum NV read/write block size.  The limit is typically set by
   the TPM property TPM_CAP_PROP_INPUT_BUFFER, munus the header and other read overhead. */

TPM_RC readNvBufferMax12(TSS_CONTEXT *tssContext,
			 uint32_t *nvBufferMax)
{
    TPM_RC			rc = 0;
    GetCapability12_In 		in;
    GetCapability12_Out		out;
    uint32_t			scap32;
    uint16_t 			written = 0;
    uint8_t 			*buffer = in.subCap;
    uint32_t			tpmBufferSize;

    if (rc == 0) {
	in.capArea = TPM_CAP_PROPERTY;
	in.subCapSize = sizeof(uint32_t);
	scap32 = TPM_CAP_PROP_INPUT_BUFFER;
	TSS_UINT32_Marshalu(&scap32, &written, &buffer, NULL);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_GetCapability,
			 TPM_RH_NULL, NULL, 0);
	if (rc != 0) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("readNvBufferMax12: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	}
    }
    if (rc == 0) {
	tpmBufferSize = ntohl(*(uint32_t *)(out.resp));
	if (verbose) printf("readNvBufferMax12: TPM_CAP_PROP_INPUT_BUFFER: %u\n", tpmBufferSize);
	*nvBufferMax = tpmBufferSize -
		       (sizeof(TPM_TAG) + sizeof(uint32_t) + sizeof(TPM_RESULT) +
			sizeof(uint32_t) +
			sizeof(TPM_NONCE) + sizeof(uint8_t) + sizeof(TPM_AUTHDATA));
	/* the Infineon TPM 1.2 fails with the optimum value 1280-55 = 1225 */
	if (*nvBufferMax > 512) {
	    *nvBufferMax = 512;
	}
	if (verbose) printf("readNvBufferMax12: nvBufferMax: %u\n", *nvBufferMax);
    }
    return rc;
}

/* getIndexSize() uses TPM_GetCapability() to return the NV index size */

TPM_RC getIndexSize12(TSS_CONTEXT *tssContext,
		      uint16_t *dataSize,
		      TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC			rc = 0;
    GetCapability12_In 		in;
    GetCapability12_Out		out;
    uint32_t			scap32;
    uint16_t 			written = 0;
    uint8_t 			*buffer = in.subCap;
    TPM_NV_DATA_PUBLIC 		ndp;
   
    if (rc == 0) {
	in.capArea = TPM_CAP_NV_INDEX;
	in.subCapSize = sizeof(uint32_t);
	scap32 = nvIndex;
	TSS_UINT32_Marshalu(&scap32, &written, &buffer, NULL);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_GetCapability,
			 TPM_RH_NULL, NULL, 0);
	if ((rc != 0) && verbose) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("getIndexSize12: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	}
    }
    if (rc == 0) {
	uint8_t 	*buffer = out.resp;
	uint32_t 	size = out.respSize;
	rc = TSS_TPM_NV_DATA_PUBLIC_Unmarshalu(&ndp, &buffer, &size);
    }
    if (rc == 0) {	/* FIXME range check */
	*dataSize = ndp.dataSize;
    }
    return rc;
}

/* getIndexContents12() uses TPM_NV_ReadValueAuth() to return the NV index contents.  It assumes the
   contents is a TPM 1.2 format certificate and returns the payload.

   It assumes owner authorization with ownerPassword password - uses NV_ReadValue.
*/

TPM_RC getIndexContents12(TSS_CONTEXT *tssContext,
			  unsigned char **ekCertificate,	/* freed by caller */	
			  uint16_t *ekCertLength,
			  TPMI_RH_NV_INDEX nvIndex,
			  const char *ownerPassword,
			  TPM_AUTHHANDLE sessionHandle,		/* OIAP session */
			  unsigned int	sessionAttributes0)	/* continue */

{
    TPM_RC		rc = 0;
    NV_ReadValue_In	in;
    NV_ReadValue_Out	out;
    uint32_t 		nvBufferMax;		/* max write in one chunk */
    uint16_t		bytesRead;		/* bytes read so far */
    int			done = FALSE;		/* done reading the certificate */
    unsigned int	sessionAttr;		/* for this chunk */

    /* maximum NV data that can be read in one chunk */
    if (rc == 0) {
	rc = readNvBufferMax12(tssContext,
			       &nvBufferMax);
    }    
    if (rc == 0) {
	if (verbose) printf("getIndexContents12: index %08x\n", nvIndex);
	in.nvIndex = nvIndex;
    }    
    /* first read the header */
    if (rc == 0) {
	in.offset = 0;
	in.dataSize = 7;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_NV_ReadValue,
			 sessionHandle, ownerPassword, 1,
			 TPM_RH_NULL, NULL, 0);
	if ((rc != 0) && verbose) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("getIndexContents12: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	}
    }
    /* validate the header and get the certificate length */
    if (rc == 0) {
	if (verbose) TSS_PrintAll("getIndexContents12: header data", out.data, out.dataSize);
	if ((out.data[0] != 0x10) ||	/* stored certificate, full certificate */
	    (out.data[1] != 0x01) ||
	    (out.data[2] != 0x00) ||	/* full certificate */
	    (out.data[5] != 0x10) ||
	    (out.data[6] != 0x02)) {
	    if (verbose) printf("getIndexContents12: certificate header error\n");
	    rc = TSS_RC_X509_ERROR;
	}
	*ekCertLength = (out.data[3] << 8) +	/* msb */
			out.data[4]
			-2;		/* -2 for tag in bytes 5 and 6 */
    }	
    if (rc == 0) {
	if (verbose) printf("getIndexContents12: certificate length %u\n", *ekCertLength);
	rc = TSS_Malloc(ekCertificate, *ekCertLength);
	bytesRead = 0;			/* certificate bytes read so far */
    }
    while ((rc == 0) && !done) {
	/* read a chunk */
	if (rc == 0) {
	    in.offset = 7 + bytesRead;
	    /* subtract safe because bytesRead can never be > *ekCertLength */
	    if ((uint32_t)(*ekCertLength - bytesRead) <= nvBufferMax) {
		in.dataSize = *ekCertLength - bytesRead;
		sessionAttr = sessionAttributes0;	/* last chunk, continue set by caller */
	    }
	    else {
		in.dataSize = nvBufferMax;		/* next chunk */
		sessionAttr = 1;			/* continue TRUE */
	    }
#if 0
	    if (verbose) printf("getIndexContents12: read %u reading %u bytes at offset %u\n",
				bytesRead, in.dataSize, in.offset);
#endif
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_ORD_NV_ReadValue,
			     sessionHandle, ownerPassword, sessionAttr,
			     TPM_RH_NULL, NULL, 0);
	    if ((rc != 0) && verbose) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("getIndexContents12: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
	    }
	}
	/* copy the results to the read buffer */
	if (rc == 0) {
	    memcpy(*ekCertificate + bytesRead, out.data, out.dataSize);
	    bytesRead += out.dataSize;
	    if (bytesRead == *ekCertLength) {
		done = TRUE;
	    }
	}
    }	
    if (rc == 0) {
	if (verbose) TSS_PrintAll("getIndexContents12: certificate",
				  *ekCertificate, *ekCertLength);
    }
    return rc;
}

