/********************************************************************************/
/*										*/
/*			     IMA Routines					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: imalib.c 963 2017-03-15 20:37:25Z kgoldman $			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2018.					*/
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

/* imalib is a set of utility functions to handle IMA (Integrity Measurement Architecture) event
   logs.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef TPM_POSIX
#include <arpa/inet.h>
#endif

#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/sha.h>
#include <openssl/engine.h>

#include <ibmtss/TPM_Types.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>

#include "imalib.h"

static uint32_t IMA_Uint32_Convert(const uint8_t *stream,
				   int littleEndian);
static uint32_t IMA_Strn2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength);

extern int verbose;

/* IMA_Event_Init() initializes the ImaEvent structure so that IMA_Event_Free() is safe.

 */

void IMA_Event_Init(ImaEvent *imaEvent)
{
    if (imaEvent != NULL) {
	imaEvent->template_data = NULL;
    }
    return;
}

/* IMA_Event_Free() frees any memory allocated for the ImaEvent structure.

 */

void IMA_Event_Free(ImaEvent *imaEvent)
{
    if (imaEvent != NULL) {
	free(imaEvent->template_data);
	imaEvent->template_data = NULL;
    }
    return;
}

/* IMA_Event_Trace() traces the ImaEvent structure.

   If traceTemplate is FALSE, template data is not traced.  This handles the case where template
   data is not unmarshaled.

*/

void IMA_Event_Trace(ImaEvent *imaEvent, int traceTemplate)
{
    printf("IMA_Event_Trace: PCR index %u\n", imaEvent->pcrIndex);
    TSS_PrintAll("IMA_Event_Trace: hash",
		 imaEvent->digest, sizeof(((ImaEvent *)NULL)->digest));

    printf("IMA_Event_Trace: name length %u\n", imaEvent->name_len);
    printf("IMA_Event_Trace: name %s\n", imaEvent->name);
    printf("IMA_Event_Trace: name integer %u\n", imaEvent->nameInt);
    printf("IMA_Event_Trace: template data length %u\n", imaEvent->template_data_len);
    /* in some use cases, the template_data field is not populated.  In those cases, do not trace
       it. */
    if (traceTemplate) {
	TSS_PrintAll("IMA_Event_Trace: template data",
		     imaEvent->template_data, imaEvent->template_data_len);
    }
    return;
}

/* IMA_TemplateData_Trace() traces the ImaTemplateData  structure.

   nameInt maps to the template name.

*/
  
void IMA_TemplateData_Trace(ImaTemplateData *imaTemplateData,
			    unsigned int nameInt)
{
    printf("IMA_TemplateData_Trace: hashLength %u\n", imaTemplateData->hashLength); 
    printf("IMA_TemplateData_Trace: hashAlg %s\n", imaTemplateData->hashAlg);
    TSS_PrintAll("IMA_Template_Trace: file data hash",
		 imaTemplateData->fileDataHash, imaTemplateData->fileDataHashLength);
    printf("IMA_TemplateData_Trace: fileNameLength %u\n", imaTemplateData->fileNameLength);
    printf("IMA_TemplateData_Trace: fileName %s\n", imaTemplateData->fileName);
    if (nameInt == IMA_SIG) {
	printf("IMA_TemplateData_Trace: sigLength %u\n", imaTemplateData->sigLength);
	if (imaTemplateData->sigLength != 0) {
	    TSS_PrintAll("IMA_TemplateData_Trace: sigHeader",
			 imaTemplateData->sigHeader, imaTemplateData->sigHeaderLength);
	    printf("IMA_TemplateData_Trace: signatureSize %u\n", imaTemplateData->signatureSize);
	    TSS_PrintAll("IMA_TemplateData_Trace: signature",
			 imaTemplateData->signature, imaTemplateData->signatureSize);
	}
    }
    return;    
}

/* IMA_Event_ReadFile() reads one IMA event from a file.

   It currently supports two SHA-1 formats:  ima-ng and ima-sig.

   This is typically used at the client, reading from the pseudofile.
*/

uint32_t IMA_Event_ReadFile(ImaEvent *imaEvent,	/* freed by caller */
			    int *endOfFile,
			    FILE *inFile,
			    int littleEndian)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;
    
    imaEvent->template_data = NULL;		/* for free */

    /* read the IMA pcr index */
    if (rc == 0) {
	readSize = fread(&(imaEvent->pcrIndex),
			 sizeof(((ImaEvent *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if (rc == 0) {
	imaEvent->pcrIndex = IMA_Uint32_Convert((uint8_t *)&imaEvent->pcrIndex, littleEndian);
    }
#if 0	/* In the future, IMA may use multiple PCRs */
    /* sanity check the PCR index */
    if (rc == 0) {
	if (imaEvent->pcrIndex != IMA_PCR) {
	    printf("ERROR: IMA_Event_ReadFile: PCR index %u not PCR %u\n",
		   imaEvent->pcrIndex, IMA_PCR);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }	
#endif
    /* read the IMA digest, this is hard coded to SHA-1 */
    if (rc == 0) {
	readSize = fread(&(imaEvent->digest),
			 sizeof(((ImaEvent *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read digest, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the IMA name length */
    if (rc == 0) {
	readSize = fread(&(imaEvent->name_len),
			 sizeof(((ImaEvent *)NULL)->name_len), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read name_len, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if (rc == 0) {
	imaEvent->name_len = IMA_Uint32_Convert((uint8_t *)&imaEvent->name_len, littleEndian);
    }
    /* bounds check the name length, leave a byte for the nul terminator */
    if (rc == 0) {
	if (imaEvent->name_len > (sizeof(((ImaEvent *)NULL)->name)) -1) {
	    printf("ERROR: IMA_Event_ReadFile: template name length too big: %u\n",
		   imaEvent->name_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the template name */
    if (rc == 0) {
	/* nul terminate first */
	memset(imaEvent->name, 0, sizeof(((ImaEvent *)NULL)->name));
	readSize = fread(&(imaEvent->name),
			 imaEvent->name_len, 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read template name, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* record the template name as an int */
    if (rc == 0) {
	if (strcmp(imaEvent->name, "ima-ng") == 0) {
		imaEvent->nameInt = IMA_NG;
	}
	else if (strcmp(imaEvent->name, "ima-sig") == 0) {
	    imaEvent->nameInt = IMA_SIG;
	}
	/* the template data parser currently supports only these two formats. */
	else {
	    imaEvent->nameInt = IMA_UNSUPPORTED;
	}
    }
    /* read the template data length */
    if (rc == 0) {
	readSize = fread(&(imaEvent->template_data_len),
			 sizeof(((ImaEvent *)NULL)->template_data_len ), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read template_data_len, "
		       " returned %lu\n", (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if (rc == 0) {
	imaEvent->template_data_len = IMA_Uint32_Convert((uint8_t *)&imaEvent->template_data_len,
							 littleEndian);
    }
    /* bounds check the template data length */
    if (rc == 0) {
	if (imaEvent->template_data_len > TCG_TEMPLATE_DATA_LEN_MAX) {
	    printf("ERROR: IMA_Event_ReadFile: template data length too big: %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	imaEvent->template_data = malloc(imaEvent->template_data_len);
	if (imaEvent->template_data == NULL) {
	    printf("ERROR: IMA_Event_ReadFile: "
		   "could not allocate template data, size %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	readSize = fread(imaEvent->template_data,
			 imaEvent->template_data_len, 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read template_data, "
		       " returned %lu\n", (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    return rc;
}

/* IMA_Event_ReadBuffer()  reads one IMA event from a buffer.

   It currently supports two SHA-1 formats:  ima-ng and ima-sig.

   This is typically used at the server, reading from a client connection.

   If getTemplate is TRUE, the template data is copied to a malloced imaEvent->template_data.  If
   FALSE, template data is skipped. FALSE is used for the first pass, where the template data is not
   needed until the hash is validated.

*/

uint32_t IMA_Event_ReadBuffer(ImaEvent *imaEvent,	/* freed by caller */
			      size_t *length,
			      uint8_t **buffer,
			      int *endOfBuffer,
			      int littleEndian,
			      int getTemplate)
{
    int rc = 0;
    
    imaEvent->template_data = NULL;		/* for free */
    if (*length == 0) {
	*endOfBuffer = 1;
    }
    else {
	/* read the IMA pcr index */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < sizeof(uint32_t)) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for PCR index\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		imaEvent->pcrIndex = IMA_Uint32_Convert(*buffer, littleEndian);
		*buffer += sizeof(uint32_t);
		*length -= sizeof(uint32_t);
	    }
	}
	/* sanity check the PCR index */
	if (rc == 0) {
	    if (imaEvent->pcrIndex != IMA_PCR) {
		printf("ERROR: IMA_Event_ReadBuffer: PCR index %u not PCR %u\n",
		       IMA_PCR, imaEvent->pcrIndex);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}	
	/* read the IMA digest, this is hard coded to SHA-1 */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < sizeof(((ImaEvent *)NULL)->digest)) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for IMA digest\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		memcpy(&(imaEvent->digest), *buffer, sizeof(((ImaEvent *)NULL)->digest));
		*buffer += sizeof(((ImaEvent *)NULL)->digest);
		*length -= sizeof(((ImaEvent *)NULL)->digest);
	    }
	}
	/* read the IMA name length */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < sizeof(uint32_t)) {
		printf("ERROR: IMA_Event_ReadBuffer: "
		       "buffer too small for IMA template name length\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		imaEvent->name_len = IMA_Uint32_Convert(*buffer, littleEndian);
		*buffer += sizeof(uint32_t);
		*length -= sizeof(uint32_t);
	    }
	}
	/* read the template name */
	if (rc == 0) {
	    /* bounds check the name length */
	    if (imaEvent->name_len > TCG_EVENT_NAME_LEN_MAX) {
		printf("ERROR: IMA_Event_ReadBuffer: Error, template name length too big: %u\n",
		       imaEvent->name_len);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else if (*length < imaEvent->name_len) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for template name\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		/* nul terminate first */
		memset(imaEvent->name, 0, sizeof(((ImaEvent *)NULL)->name));
		memcpy(&(imaEvent->name), *buffer, imaEvent->name_len);
		*buffer += imaEvent->name_len;
		*length -= imaEvent->name_len;
	    }
	}
	/* record the template name as an int */
	if (rc == 0) {
	    if (strcmp(imaEvent->name, "ima-ng") == 0) {
		imaEvent->nameInt = IMA_NG;
	    }
	    else if (strcmp(imaEvent->name, "ima-sig") == 0) {
		imaEvent->nameInt = IMA_SIG;
	    }
	    /* the template data parser currently supports only these two formats. */
	    else {
		imaEvent->nameInt = IMA_UNSUPPORTED;
	    }
	}
	/* read the template data length */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < sizeof(uint32_t)) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for template data length\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		imaEvent->template_data_len = IMA_Uint32_Convert(*buffer, littleEndian);
		*buffer += sizeof(uint32_t);
		*length -= sizeof(uint32_t);
	    }
	}
	/* allocate for the template data */
	if (rc == 0) {
	    if (getTemplate) {
		/* bounds check the template data length */
		if (imaEvent->template_data_len > TCG_TEMPLATE_DATA_LEN_MAX) {
		    printf("ERROR: IMA_Event_ReadBuffer: template data length too big: %u\n",
			   imaEvent->template_data_len );
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
		else if (*length < imaEvent->template_data_len) {
		    printf("ERROR: IMA_Event_ReadBuffer: buffer too small for template data\n");
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
		else {
		    if (rc == 0) {
			imaEvent->template_data = malloc(imaEvent->template_data_len);
			if (imaEvent->template_data == NULL) {
			    printf("ERROR: IMA_Event_ReadBuffer: "
				   "could not allocate template data, size %u\n",
				   imaEvent->template_data_len);
			    rc = TSS_RC_INSUFFICIENT_BUFFER;
			}
		    }
		    if (rc == 0) {
			memcpy(imaEvent->template_data, *buffer, imaEvent->template_data_len);
		    }
		}
	    }
	    /* move the buffer even if getTemplate is false */
	    if (rc == 0) {
		*buffer += imaEvent->template_data_len;
		*length -= imaEvent->template_data_len;
	    }
	}
    }
    return rc;
}

/* IMA_TemplateData_ReadBuffer() unmarshals the template data fields from the template data byte
   array.

   It currently supports two SHA-1 formats:  ima-ng and ima-sig.
*/

uint32_t IMA_TemplateData_ReadBuffer(ImaTemplateData *imaTemplateData,
				     ImaEvent *imaEvent,
				     int littleEndian)
{
    int 	rc = 0;
    size_t 	length = imaEvent->template_data_len;
    uint8_t 	*buffer = imaEvent->template_data;

    /* check for supported template name */
    if (rc == 0) {
	if (imaEvent->nameInt == IMA_UNSUPPORTED) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: template name %s unsupported\n",
		   imaEvent->name);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }    
    /* read the hash length, algorithm + hash */
    if (rc == 0) {
	/* bounds check the length */
	if (length < sizeof(uint32_t)) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: buffer too small for hash length\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    imaTemplateData->hashLength = IMA_Uint32_Convert(buffer, littleEndian);
	    buffer += sizeof(uint32_t);
	    length -= sizeof(uint32_t);
	}
    }
    /* read the hash algorithm, nul terminated string */
    size_t hashAlgSize;
    if (rc == 0) {
    	/* NUL terminate first */
	memset(imaTemplateData->hashAlg, 0, sizeof(((ImaTemplateData *)NULL)->hashAlg));
	rc = IMA_Strn2cpy(imaTemplateData->hashAlg, buffer,
			  sizeof(((ImaTemplateData *)NULL)->hashAlg),	/* destLength */
			  imaTemplateData->hashLength);			/* srcLength */
	if (rc != 0) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: buffer too small for hash algorithm\n"
		   "\tor hash algorithm exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    hashAlgSize = strlen(imaTemplateData->hashAlg) + 1;
	    buffer += hashAlgSize;
	    length -= hashAlgSize;
	}
    }
    /* fileDataHashLength */
    if (rc == 0) {
	if (strcmp(imaTemplateData->hashAlg, "sha1:") == 0) {
	    imaTemplateData->fileDataHashLength = SHA1_DIGEST_SIZE;
	    imaTemplateData->hashNid = NID_sha1;
	}
	else if (strcmp(imaTemplateData->hashAlg, "sha256:") == 0) {
	    imaTemplateData->fileDataHashLength = SHA256_DIGEST_SIZE;
	    imaTemplateData->hashNid = NID_sha256;
	}
	else {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: Unknown file data hash algorithm: %s\n",
		   imaTemplateData->hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* consistency check hashLength vs contents */
    if (rc == 0) {
	if ((hashAlgSize + imaTemplateData->fileDataHashLength) != imaTemplateData->hashLength) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: "
		   "hashLength %u inconsistent with hashAlgSize %lu and fileDataHashLength %u\n",
		   imaTemplateData->hashLength, (unsigned long)hashAlgSize,
		   imaTemplateData->fileDataHashLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* fileDataHash */
    if (rc == 0) {
	/* bounds check the length */
	if (length < imaTemplateData->fileDataHashLength) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: buffer too small for file data hash\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->fileDataHashLength >
		 sizeof(((ImaTemplateData *)NULL)->fileDataHash)) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: "
		   "file data hash length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	} 
	else {
	    memcpy(&(imaTemplateData->fileDataHash), buffer, imaTemplateData->fileDataHashLength);
	    buffer += imaTemplateData->fileDataHashLength;
	    length -= imaTemplateData->fileDataHashLength;
	}
    }    
    /* fileNameLength (length includes the nul terminator)*/
    if (rc == 0) {
	/* bounds check the length */
	if (length < sizeof(uint32_t)) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: buffer too small for file name length\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    imaTemplateData->fileNameLength = IMA_Uint32_Convert(buffer, littleEndian);
	    buffer += sizeof(uint32_t);
	    length -= sizeof(uint32_t);
	}
    }
    /* fileName */
    if (rc == 0) {
	/* bounds check the length */
	if (length < imaTemplateData->fileNameLength) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: buffer too small for file name\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->fileNameLength > (MAXPATHLEN+1)) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: file name length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    memcpy(&(imaTemplateData->fileName), buffer, imaTemplateData->fileNameLength);
	    buffer += imaTemplateData->fileNameLength;
	    length -= imaTemplateData->fileNameLength;
	}
    }
    /* sanity check nul terminator */
    if (rc == 0) {
	if (imaTemplateData->fileName[imaTemplateData->fileNameLength - 1] != '\0') {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: file name not nul terminated\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (imaEvent->nameInt == IMA_SIG) {
	/* sigLength */
	if (rc == 0) {
	    /* bounds check the length */
	    if (length < sizeof(uint32_t)) {
		printf("ERROR: IMA_TemplateData_ReadBuffer: "
		       "buffer too small for signature length\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		imaTemplateData->sigLength = IMA_Uint32_Convert(buffer, littleEndian);
		buffer += sizeof(uint32_t);
		length -= sizeof(uint32_t);
	    }
	    /* sigHeader - only parsed if its length is not zero */
	    if (imaTemplateData->sigLength != 0) {
		if (rc == 0) {
		    imaTemplateData->sigHeaderLength = sizeof((ImaTemplateData *)NULL)->sigHeader;
		    /* bounds check the length */
		    if (length < imaTemplateData->sigHeaderLength) {
			printf("ERROR: IMA_TemplateData_ReadBuffer: "
			       "buffer too small for signature header\n");
			rc = TSS_RC_INSUFFICIENT_BUFFER;
		    }
		    else {
			memcpy(&(imaTemplateData->sigHeader), buffer,
			       imaTemplateData->sigHeaderLength);
			buffer += imaTemplateData->sigHeaderLength;
			length -= imaTemplateData->sigHeaderLength;
		    }
		}
		/* get signature length from last two bytes */
		if (rc == 0) {
		    /* magic number for offset: type(1) version(1) hash alg (1) pubkey id (4) */
		    imaTemplateData->signatureSize =
			ntohs(*(uint16_t *)(imaTemplateData->sigHeader + 7));
		}
		/* consistency check signature header contents */
		if (rc == 0) {
		    int goodHashAlgo = (((imaTemplateData->sigHeader[2] == HASH_ALGO_SHA1) &&
					 (imaTemplateData->hashNid = NID_sha1)) ||
					((imaTemplateData->sigHeader[2] == HASH_ALGO_SHA256) &&
					 (imaTemplateData->hashNid = NID_sha256)));
		    int goodSigSize = ((imaTemplateData->signatureSize == 128) ||
				       (imaTemplateData->signatureSize == 256));
		    /* xattr type */
		    if (
			(imaTemplateData->sigHeader[0] != EVM_IMA_XATTR_DIGSIG) || /* [0] type */
			(imaTemplateData->sigHeader[1] != 2) ||		/* [1] version */
			!goodHashAlgo ||				/* [2] hash algorithm */
			/* [3]-[6] are the public key fingerprint.  Any value is legal. */
			!goodSigSize 					/* [7][8] sig size */
			) {
			printf("ERROR: IMA_TemplateData_ReadBuffer: invalid sigHeader\n");
			rc = TSS_RC_INSUFFICIENT_BUFFER;
		    }
		}
		/* signature */
		if (rc == 0) {
		    /* bounds check the length */
		    if (length < imaTemplateData->signatureSize) {
			printf("ERROR: IMA_TemplateData_ReadBuffer: "
			       "buffer too small for signature \n");
			rc = TSS_RC_INSUFFICIENT_BUFFER;
		    }
		    /* sanity check the signatureSize against the sigLength */
		    else if (imaTemplateData->sigLength !=
			     (sizeof((ImaTemplateData *)NULL)->sigHeader +
			      imaTemplateData->signatureSize)) {
			printf("ERROR: IMA_TemplateData_ReadBuffer: "
			       "sigLength inconsistent with signatureSize\n");
			rc = TSS_RC_INSUFFICIENT_BUFFER;
		    }
		    else {
			memcpy(&(imaTemplateData->signature), buffer,
			       imaTemplateData->signatureSize);
			buffer += imaTemplateData->signatureSize;
			length -= imaTemplateData->signatureSize;
		    }
		}
	    }
	}
    }
    /* length should now be zero */
    if (rc == 0) {
	if (length != 0) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: "
		   "buffer too large (bytes remaining after unmarshaling)\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }    
    return rc;
}

/* IMA_Event_Write() writes an event line to a binary file outFile.

   The write is always big endian, network byte order.
*/

uint32_t IMA_Event_Write(ImaEvent *imaEvent,
			 FILE *outFile)
{
    int rc = 0;
    size_t writeSize;
    uint32_t nbo32;	/* network byte order */

    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->pcrIndex);
	/* write the IMA pcr index */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write pcrIndex, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the IMA digest, name length */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->digest), sizeof(((ImaEvent *)NULL)->digest), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write digest, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the IMA name length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->name_len);
	/* write the IMA name length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write name length, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the name */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->name), imaEvent->name_len, 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write name, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the template data length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->template_data_len);
	/* write the IMA template data length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not template data length , returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the template data */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->template_data), imaEvent->template_data_len, 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write template data, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    return rc;
}

/* IMA_Extend() extends the event into the imaPcr.

   An IMA quirk is that, if the event is all zero, all ones is extended into the SHA-1 bank.  Since
   the SHA-256 bank currently gets the SHA-1 value zero extended, it will get 20 ff's and 12 00's.

   halg indicates whether to calculate the digest for the SHA-1 or SHA-256 PCR bank.  The IMA event
   log itself is always SHA-1.

   This function assumes that the same hash algorithm / PCR bank is used for all calls.
*/

uint32_t IMA_Extend(TPMT_HA *imapcr,
		    ImaEvent *imaEvent,
		    TPMI_ALG_HASH hashAlg)
{
    uint32_t 		rc = 0;
    uint16_t		digestSize;
    uint16_t		zeroPad;
    int 		notAllZero;
    unsigned char zeroDigest[SHA256_DIGEST_SIZE];
    unsigned char oneDigest[SHA256_DIGEST_SIZE];

    /* FIXME sanity check TPM_IMA_PCR imaEvent->pcrIndex */
    
    /* extend based on the previous IMA PCR value */
    if (rc == 0) {
	memset(zeroDigest, 0, SHA256_DIGEST_SIZE);
	memset(oneDigest, 0xff, SHA256_DIGEST_SIZE);
	if (hashAlg == TPM_ALG_SHA1) {
	    digestSize = SHA1_DIGEST_SIZE;
	    zeroPad = 0;
	}
	else if (hashAlg == TPM_ALG_SHA256) {
	    digestSize = SHA256_DIGEST_SIZE;
	    /* pad the SHA-1 event with zeros for the SHA-256 bank */
	    zeroPad = SHA256_DIGEST_SIZE - SHA1_DIGEST_SIZE;
	}
	else {
	    printf("ERROR: IMA_Extend: Unsupported hash algorithm: %04x\n", hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    if (rc == 0) {
	notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
	imapcr->hashAlg = hashAlg;
	if (notAllZero) {
#if 0
	    TSS_PrintAll("IMA_Extend: Start PCR", (uint8_t *)&imapcr->digest, digestSize);
	    TSS_PrintAll("IMA_Extend: Extend", (uint8_t *)&imaEvent->digest, SHA1_DIGEST_SIZE);
	    TSS_PrintAll("IMA_Extend: Pad", zeroDigest, zeroPad);
#endif
	    rc = TSS_Hash_Generate(imapcr,
				   digestSize, (uint8_t *)&imapcr->digest,
				   SHA1_DIGEST_SIZE, &imaEvent->digest,
				   /* SHA-1 PCR extend gets zero padded */
				   zeroPad, zeroDigest,
				   0, NULL);
	}
	/* IMA has a quirk where, when it places all all zero digest into the measurement log, it
	   extends all ones into IMA PCR */
	else {
	    rc = TSS_Hash_Generate(imapcr,
				   digestSize, (uint8_t *)&imapcr->digest,
				   digestSize, oneDigest,
				   /* SHA-1 gets zero padded */
				   zeroPad, zeroDigest,
				   0, NULL);
	}
    }
    if (rc != 0) {
	printf("ERROR: IMA_Extend: could not extend imapcr, rc %08x\n", rc);
    }
    return rc;
}

/* IMA_VerifyImaDigest() verifies the IMA digest against the hash of the template data.

   This handles the SHA-1 IMA event log.
*/

uint32_t IMA_VerifyImaDigest(uint32_t *badEvent, /* TRUE if hash does not match */
			     ImaEvent *imaEvent, /* the current IMA event being processed */
			     int eventNum)	 /* the current IMA event number being processed */
{
    uint32_t 	rc = 0;
    int		irc;
    
    /* calculate the hash of the template data */
    TPMT_HA calculatedImaDigest;
    if (rc == 0) {
	calculatedImaDigest.hashAlg = TPM_ALG_SHA1;
	rc = TSS_Hash_Generate(&calculatedImaDigest,
			       imaEvent->template_data_len, imaEvent->template_data,
			       0, NULL);
    }
    /* compare the calculated hash to the event digest received from the client */
    if (rc == 0) {
	if (verbose) TSS_PrintAll("IMA_VerifyImaDigest: Received IMA digest",
				   imaEvent->digest, SHA1_DIGEST_SIZE);
	if (verbose) TSS_PrintAll("IMA_VerifyImaDigest: Calculated IMA digest",
				   (uint8_t *)&calculatedImaDigest.digest, SHA1_DIGEST_SIZE);

	irc = memcmp(imaEvent->digest, &calculatedImaDigest.digest, SHA1_DIGEST_SIZE);
	if (irc == 0) {
	    if (verbose) printf("IMA_VerifyImaDigest: IMA digest verified, event %u\n", eventNum);
	    *badEvent = FALSE;
	}
	else {
	    printf("ERROR: IMA_VerifyImaDigest: IMA digest did not verify, event %u\n",
		   eventNum);
	    *badEvent = TRUE;
	}
    }
    return rc;
}

/* IMA_Uint32_Convert() converts a uint8_t (from an input stream) to host byte order
 */

static uint32_t IMA_Uint32_Convert(const uint8_t *stream,
				   int littleEndian)
{
    uint32_t out = 0;

    /* little endian input */
    if (littleEndian) {
	out = (stream[0] <<  0) |
	      (stream[1] <<  8) |
	      (stream[2] << 16) |
	      (stream[3] << 24);
    }
    /* big endian input */
    else {
	out = (stream[0] << 24) |
	      (stream[1] << 16) |
	      (stream[2] <<  8) |
	      (stream[3] <<  0);
    }
    return out;
}

/* IMA_Strn2cpy() copies src to dest, including a NUL terminator

   It checks that src is nul terminated within srcLength bytes.
   It checks that src fits into dest within destLength bytes

   Returns error if either the src is not nul terminated or will not fit in dest.
*/

static uint32_t IMA_Strn2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength)
{
    uint32_t rc = 0;
    int done = 0;
    
    while ((destLength > 0) && (srcLength > 0)) {
	*dest = *src;
	if (*dest == '\0') {
	    done = 1;
	    break;
	}
	else {
	    dest++;
	    src++;
	    destLength--;
	    srcLength--;
	}
    }
    if (!done) {
	rc = TSS_RC_INSUFFICIENT_BUFFER;
    }
    return rc;
}

/* IMA_Event_Marshal() marshals an ImaEvent structure */

TPM_RC IMA_Event_Marshal(ImaEvent *source,
			 uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->name_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->name, source->name_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->template_data_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->template_data, source->template_data_len,
			       written, buffer, size);
    }
    return rc;
}

/* IMA_Event_PcrExtend() extends PCR digests with the digest from the ImaEvent event log
   entry.

   Bank 0 is SHA-1.  Bank 1 is SHA-256.

   The function supports all PCRs, even though the PCRs are limited in practice.

*/

uint32_t IMA_Event_PcrExtend(TPMT_HA pcrs[IMA_PCR_BANKS][IMPLEMENTATION_PCR],
			     ImaEvent *imaEvent)
{
    TPM_RC 		rc = 0;
    uint8_t		eventData[SHA256_DIGEST_SIZE];
    
    /* validate PCR number */
    if (rc == 0) {
	if (imaEvent->pcrIndex > IMPLEMENTATION_PCR) {
	    printf("ERROR: IMA_Event_PcrExtend: PCR number %u out of range\n", imaEvent->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    /* process each event hash algorithm */
    if (rc == 0) {
	unsigned char 	zeroDigest[SHA1_DIGEST_SIZE];
	memset(zeroDigest, 0, SHA1_DIGEST_SIZE);
	int notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
	/* for the SHA-256 zero extend */
	memset(eventData, 0, SHA256_DIGEST_SIZE);
	
	/* IMA has a quirk where some measurements store a zero digest in the event log, but
	   extend ones into PCR 10 */
	if (notAllZero) {
	    memcpy(eventData, imaEvent->digest, SHA1_DIGEST_SIZE);
	}
	else {
	    memset(eventData, 0xff, SHA1_DIGEST_SIZE);
	}
    }
    /* SHA-1 */
    if (rc == 0) {
	rc = TSS_Hash_Generate(&pcrs[0][imaEvent->pcrIndex],
			       SHA1_DIGEST_SIZE,
			       (uint8_t *)&pcrs[0][imaEvent->pcrIndex].digest,
			       SHA1_DIGEST_SIZE,
			       eventData,
			       0, NULL);
    }
    /* SHA-256 */
    if (rc == 0) {
	rc = TSS_Hash_Generate(&pcrs[1][imaEvent->pcrIndex],
			       SHA256_DIGEST_SIZE,
			       (uint8_t *)&pcrs[1][imaEvent->pcrIndex].digest,
			       SHA256_DIGEST_SIZE,
			       eventData,
			       0, NULL);
    }
    return rc;
}

#if 0
/* IMA_Event_ToString() converts the ImaEvent structure to a hexascii string, big endian. */

uint32_t IMA_Event_ToString(char **eventString,	/* freed by caller */
			    ImaEvent *imaEvent)
{
    int 	rc = 0;
    size_t	length;
    
    /* calculate size of string, from ImaEvent structure */
    if (rc == 0) {
	length = ((sizeof(uint32_t) + SHA1_DIGEST_SIZE + sizeof(uint32_t) +
		   TCG_EVENT_NAME_LEN_MAX + 1 + sizeof(uint32_t) +
		   imaEvent->template_data_len) * 2) + 1;
    }
    if (rc == 0) {
	*eventString = malloc(length);
	if (*eventString == NULL) {
	    printf("ERROR: IMA_Event_ToString: error allocating %lu bytes\n", length);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	memset(*eventString, '\0', length);
	char *p = *eventString;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->pcrIndex);
	p += sizeof(uint32_t)* 2;

	Array_Print(p, NULL, imaEvent->digest, SHA1_DIGEST_SIZE);
	p += SHA1_DIGEST_SIZE * 2;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->name_len);
	p += sizeof(uint32_t) * 2;

	Array_Print(p, NULL, FALSE, (uint8_t *)imaEvent->name, imaEvent->name_len);
	p += imaEvent->name_len * 2;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->template_data_len);
	p += sizeof(uint32_t) * 2;

	Array_Print(p, NULL, FALSE, imaEvent->template_data, imaEvent->template_data_len);
	p += imaEvent->template_data_len * 2;
	/* printf("IMA_Event_ToString: result\n:%s:\n", *eventString); */
    }
    return rc;
}

#endif

