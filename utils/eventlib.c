/********************************************************************************/
/*										*/
/*		     	TPM2 Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2020.					*/
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
#include <inttypes.h>

#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsserror.h>
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#endif /* TPM_TSS_NOCRYPTO */
#include <ibmtss/tssutils.h>

#include "eventlib.h"
#include "efilib.h"

#ifdef HAVE_CONFIG_H
/*
  * config.h is only present if autoconf was used, which is only the
  * linux builds
  */
#include <config.h>
#endif
#ifdef HAVE_EFIBOOT_H
/* This is set by the autoconf checks for the efiboot/efivar packages

   On Ubuntu, the packages are libefivar-dev libefiboot-dev and possibly efivar efitools
*/

#include <efivar/efiboot.h>
#endif

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
static uint16_t Uint16_Convert(uint16_t in);
#endif
static uint32_t Uint32_Convert(uint32_t in);
#endif /* TPM_TSS_NOFILE */
static void TSS_EVENT_EventType_Trace(uint32_t eventType);
static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size);
static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize);
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target,
						   BYTE **buffer,
						   uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer,
					uint32_t *size, BOOL allowNull);
static TPM_RC TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target,
					      BYTE **buffer, uint32_t *size,
					      BOOL allowNull);
static TPM_RC TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target,
					   BYTE **buffer, uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
				      BYTE **buffer, uint32_t *size);
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
						 uint16_t *written, BYTE **buffer,
						 uint32_t *size);

/* TSS_EVENT_Line_Read() reads a TPM 1.2 SHA-1 event line from a binary file inFile.

 */

#ifndef TPM_TSS_NOFILE
int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			int *endOfFile,
			FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long) readSize);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the digest */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->digest),
			 sizeof(((TCG_PCR_EVENT *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read digest, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event data size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventDataSize),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventDataSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event data size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventDataSize = Uint32_Convert(event->eventDataSize);
    }
    /* bounds check the event data length */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventDataSize > sizeof(((TCG_PCR_EVENT *)NULL)->event)) {
	    printf("TSS_EVENT_Line_Read: Error, event data length too big: %u\n",
		   event->eventDataSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventDataSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT_Line_Marshal() marshals a TCG_PCR_EVENT structure */

TPM_RC TSS_EVENT_Line_Marshal(TCG_PCR_EVENT *source,
			      uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventDataSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->event, source->eventDataSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure

 */

TPM_RC TSS_EVENT_Line_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT_Line_LE_Unmarshal() Unmarshal LE buffer into a target TCG_PCR_EVENT
*/
TPM_RC TSS_EVENT_Line_LE_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
/* TSS_EVENT_PCR_Extend() extends PCR digest with the digest from the TCG_PCR_EVENT event log
   entry.
*/

TPM_RC TSS_EVENT_PCR_Extend(TPMT_HA pcrs[IMPLEMENTATION_PCR],
			    TCG_PCR_EVENT *event)
{
    TPM_RC 		rc = 0;
    
    /* validate PCR number */
    if (rc == 0) {
	if (event->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: TSS_EVENT_PCR_Extend: PCR number %u out of range\n", event->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* process each event hash algorithm */
    if (rc == 0) {
	pcrs[event->pcrIndex].hashAlg = TPM_ALG_SHA1;	/* should already be initialized */
	if (rc == 0) {
	    rc = TSS_Hash_Generate(&pcrs[event->pcrIndex],
				   SHA1_DIGEST_SIZE, (uint8_t *)&pcrs[event->pcrIndex].digest,
				   SHA1_DIGEST_SIZE, &event->digest,
				   0, NULL);
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOCRYPTO */

void TSS_EVENT_Line_Trace(TCG_PCR_EVENT *event)
{
    printf("TSS_EVENT_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    TSS_PrintAll("TSS_EVENT_Line_Trace: PCR",
		 event->digest, sizeof(((TCG_PCR_EVENT *)NULL)->digest));
    TSS_PrintAll("TSS_EVENT_Line_Trace: event",
		 event->event, event->eventDataSize);
    if (event->eventType == EV_IPL) {	/* this event appears to be printable strings */
	printf(" %.*s\n", event->eventDataSize, event->event);
    }
    return;
}

/* TSS_SpecIdEvent_Unmarshal() unmarshals the TCG_EfiSpecIDEvent structure.

   The size and buffer are not moved, since this is the only structure in the event.
*/

TPM_RC TSS_SpecIdEvent_Unmarshal(TCG_EfiSpecIDEvent *specIdEvent,
				 uint32_t eventSize,
				 uint8_t *event)
{
    TPM_RC	rc = 0;
    uint32_t	size = eventSize;	/* copy, because size and buffer are not moved */
    uint8_t	*buffer = event;
    uint32_t 	i;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->signature, sizeof(specIdEvent->signature),
			     &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&(specIdEvent->platformClass), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMinor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMajor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specErrata), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->uintnSize), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&(specIdEvent->numberOfAlgorithms), &buffer, &size);
    }
    for (i = 0 ; (rc == 0) && (i < specIdEvent->numberOfAlgorithms) ; i++) {
	rc = TSS_SpecIdEventAlgorithmSize_Unmarshal(&(specIdEvent->digestSizes[i]),
						    &buffer, &size);
    }	    
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->vendorInfoSize), &buffer, &size);
    }
#if 0	/* NOTE: Can never fail because vendorInfoSize is uint8_t and vendorInfo is 0xff bytes */
    if (rc == 0) {
	if (specIdEvent->vendorInfoSize > sizeof(specIdEvent->vendorInfo)) {
	    rc = TPM_RC_SIZE;
	}
    }    
#endif
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->vendorInfo, specIdEvent->vendorInfoSize,
			     &buffer, &size);
    }
    return rc;
}

/* TSS_SpecIdEventAlgorithmSize_Unmarshal() unmarshals the TCG_EfiSpecIdEventAlgorithmSize
   structure */

static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size)
{
    TPM_RC	rc = 0;

    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&(algSize->algorithmId), buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&(algSize->digestSize), buffer, size);
    } 
    if (rc == 0) {
	uint16_t mappedDigestSize = TSS_GetDigestSize(algSize->algorithmId);
	if (mappedDigestSize != 0) {
	    if (mappedDigestSize != algSize->digestSize) {
		printf("TSS_SpecIdEventAlgorithmSize_Unmarshal: "
		       "Error, inconsistent digest size, algorithm %04x size %u\n",
		       algSize->algorithmId, algSize->digestSize);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
    }
    return rc;
}

void TSS_SpecIdEvent_Trace(TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t 	i;

    /* normal case */
    if (specIdEvent->signature[15] == '\0')  {
	printf("TSS_SpecIdEvent_Trace: signature: %s\n", specIdEvent->signature);
    }
    /* error case */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: signature",
		     specIdEvent->signature, sizeof(specIdEvent->signature));
    }
    printf("TSS_SpecIdEvent_Trace: platformClass %08x\n", specIdEvent->platformClass);
    printf("TSS_SpecIdEvent_Trace: specVersionMinor %02x\n", specIdEvent->specVersionMinor);
    printf("TSS_SpecIdEvent_Trace: specVersionMajor %02x\n", specIdEvent->specVersionMajor);
    printf("TSS_SpecIdEvent_Trace: specErrata %02x\n", specIdEvent->specErrata);
    printf("TSS_SpecIdEvent_Trace: uintnSize %02x\n", specIdEvent->uintnSize);
    printf("TSS_SpecIdEvent_Trace: numberOfAlgorithms %u\n", specIdEvent->numberOfAlgorithms);
    for (i = 0 ; (i < specIdEvent->numberOfAlgorithms) ; i++) {
	TSS_SpecIdEventAlgorithmSize_Trace(&(specIdEvent->digestSizes[i]));
    }
    /* try for a printable string */
    if (specIdEvent->vendorInfoSize > 0) {
	if (specIdEvent->vendorInfo[specIdEvent->vendorInfoSize-1] == '\0')  {
	    printf("TSS_SpecIdEvent_Trace: vendorInfo: %s\n", specIdEvent->vendorInfo);
	}
    }
    /* if not, trace the bytes */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: vendorInfo",
		     specIdEvent->vendorInfo, specIdEvent->vendorInfoSize);
    }
    return;
}

static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize)
{
    printf("TSS_SpecIdEventAlgorithmSize_Trace: algorithmId %04x\n", algSize->algorithmId);
    printf("TSS_SpecIdEventAlgorithmSize_Trace: digestSize %u\n", algSize->digestSize);
    return;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOFILE

/* TSS_EVENT2_Line_Read() reads a TPM2 event line from a binary file inFile.

*/

int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event,
			 int *endOfFile,
			 FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    uint32_t maxCount; 
    uint32_t count;

    *endOfFile = FALSE;
    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT2_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the TPML_DIGEST_VALUES count */
    if (!*endOfFile && (rc == 0)) {
	maxCount = sizeof((TPML_DIGEST_VALUES *)NULL)->digests / sizeof(TPMT_HA);
	readSize = fread(&(event->digests.count),
			 sizeof(((TPML_DIGEST_VALUES *)NULL)->count), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read digest count, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->digests.count = Uint32_Convert(event->digests.count);
    }
    /* range check the digest count */
    if (!*endOfFile && (rc == 0)) {
	if (event->digests.count > maxCount) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count %u is greater than structure %u\n",
		   event->digests.count, maxCount);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (event->digests.count == 0) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count is zero\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read all the TPMT_HA, loop through all the digest algorithms */
    for (count = 0 ; !*endOfFile && (count < event->digests.count) ; count++) {
	uint16_t digestSize;
	/* read the digest algorithm */
	if (rc == 0) {
	    readSize = fread(&(event->digests.digests[count].hashAlg),
			     sizeof((TPMT_HA *)NULL)->hashAlg, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: "
		       "Error, could not read digest algorithm, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* do the endian conversion of the hash algorithm from stream to uint16_t */
	if (rc == 0) {
	    event->digests.digests[count].hashAlg =
		Uint16_Convert(event->digests.digests[count].hashAlg);
	}
	/* map from the digest algorithm to the digest length */
	if (rc == 0) {
	    digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	    if (digestSize == 0) {
		printf("TSS_EVENT2_Line_Read: Error, unknown digest algorithm %04x*\n",
		       event->digests.digests[count].hashAlg);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* read the digest */
	if (rc == 0) {
	    readSize = fread((uint8_t *)&(event->digests.digests[count].digest),
			     digestSize, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: Error, could not read digest, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the event size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventSize),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventSize = Uint32_Convert(event->eventSize);
    }
    /* bounds check the event size */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventSize > sizeof(((TCG_PCR_EVENT2 *)NULL)->event)) {
	    printf("TSS_EVENT2_Line_Read: Error, event size too big: %u\n",
		   event->eventSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (event->eventSize > 0) && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT2 *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT2_Line_Marshal() marshals a TCG_PCR_EVENT2 structure */

TPM_RC TSS_EVENT2_Line_Marshal(TCG_PCR_EVENT2 *source,
			       uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Marshal() Marshals a TSS_EVENT2 structure from HBO into LE
 * and saves to buffer.
 */
TPM_RC TSS_EVENT2_Line_LE_Marshal(TCG_PCR_EVENT2 *source, uint16_t *written,
				  uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT2_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure */


TPM_RC TSS_EVENT2_Line_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Unmarshal() Unmarshals an LE eventlog buffer and save to
 * the target TCG_PCR_EVENT2
 */
TPM_RC TSS_EVENT2_Line_LE_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
/* TSS_EVENT2_PCR_Extend() extends PCR digests with the digest from the TCG_PCR_EVENT2 event log
   entry.
*/

TPM_RC TSS_EVENT2_PCR_Extend(TPMT_HA pcrs[HASH_COUNT][IMPLEMENTATION_PCR],
			     TCG_PCR_EVENT2 *event2)
{
    TPM_RC 		rc = 0;
    uint32_t 		i;		/* iterator though hash algorithms */
    uint32_t 		bankNum = 0;	/* iterator though PCR hash banks */
    
    /* validate PCR number */
    if (rc == 0) {
	if (event2->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR number %u out of range\n", event2->pcrIndex);
	    rc = 1;
	}
    }
    /* validate event count */
    if (rc == 0) {
	uint32_t maxCount = sizeof(((TPML_DIGEST_VALUES *)NULL)->digests) / sizeof(TPMT_HA);
	if (event2->digests.count > maxCount) {
	    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR count %u out of range, max %u\n",
		   event2->digests.count, maxCount);
	    rc = 1;
	}	    
    }
    /* process each event hash algorithm */
    for (i = 0; (rc == 0) && (i < event2->digests.count) ; i++) {
	/* find the matching PCR bank */
	for (bankNum = 0 ; (rc == 0) && (bankNum < event2->digests.count) ; bankNum++) {
	    if (pcrs[bankNum][0].hashAlg == event2->digests.digests[i].hashAlg) {

		uint16_t digestSize;
		if (rc == 0) {
		    digestSize = TSS_GetDigestSize(event2->digests.digests[i].hashAlg);
		    if (digestSize == 0) {
			printf("ERROR: TSS_EVENT2_PCR_Extend: hash algorithm %04hx unknown\n",
			       event2->digests.digests[i].hashAlg);
			rc = 1;
		    }
		}
		if (rc == 0) {
		    rc = TSS_Hash_Generate(&pcrs[bankNum][event2->pcrIndex],
					   digestSize,
					   (uint8_t *)&pcrs[bankNum][event2->pcrIndex].digest,
					   digestSize,
					   &event2->digests.digests[i].digest,
					   0, NULL);
		}
	    }
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOCRYPTO */
#endif	/* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* Uint16_Convert() converts a little endian uint16_t (from an input stream) to host byte order
 */

static uint16_t Uint16_Convert(uint16_t in)
{
    uint16_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8);
    return out;
}

#endif

/* Uint32_Convert() converts a little endian uint32_t (from an input stream) to host byte order
 */

static uint32_t Uint32_Convert(uint32_t in)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8) |
	  (inb[2] << 16) |
	  (inb[3] << 24);
    return out;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_UINT16LE_Unmarshal() unmarshals a little endian 2-byte array from buffer into a HBO uint16_t */

TPM_RC TSS_UINT16LE_Unmarshal(uint16_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint16_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint16_t)((*buffer)[0]) <<  0) |
	      ((uint16_t)((*buffer)[1]) <<  8);
    *buffer += sizeof(uint16_t);
    *size -= sizeof(uint16_t);
    return TPM_RC_SUCCESS;
}

/* TSS_UINT32LE_Unmarshal() unmarshals a little endian 4-byte array from buffer into a HBO uint32_t */

TPM_RC TSS_UINT32LE_Unmarshal(uint32_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint32_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint32_t)((*buffer)[0]) <<  0) |
	      ((uint32_t)((*buffer)[1]) <<  8) |
	      ((uint32_t)((*buffer)[2]) << 16) |
	      ((uint32_t)((*buffer)[3]) << 24);
    *buffer += sizeof(uint32_t);
    *size -= sizeof(uint32_t);
    return TPM_RC_SUCCESS;
}

/* TSS_UINT64LE_Unmarshal() unmarshals a little endian 8-byte array from buffer into a HBO uint64_t */

TPM_RC TSS_UINT64LE_Unmarshal(uint64_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint64_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint64_t)((*buffer)[0]) <<  0) |
	      ((uint64_t)((*buffer)[1]) <<  8) |
	      ((uint64_t)((*buffer)[2]) << 16) |
	      ((uint64_t)((*buffer)[3]) << 24) |
	      ((uint64_t)((*buffer)[4]) << 32) |
	      ((uint64_t)((*buffer)[5]) << 40) |
	      ((uint64_t)((*buffer)[6]) << 48) |
	      ((uint64_t)((*buffer)[7]) << 56);
    *buffer += sizeof(uint64_t);
    *size -= sizeof(uint64_t);
    return TPM_RC_SUCCESS;
}

#ifdef HAVE_EFIBOOT_H
/* This section contains parsers for boot options requiring efiboot.h */
static void load_option_printf(void *o, uint64_t lo_len)
{
    efi_load_option *lo = o;
    efidp efidp;
    const unsigned char *desc;
    int pathlen;
    unsigned char *text_path;
    int text_path_len;
    int rc;
    //unsigned char *c = o;

    if (!efi_loadopt_is_valid(lo, lo_len)) {
	printf("\n  <Invalid load option>\n");
	return;
    }
    printf("\n  Enabled: %s", (efi_loadopt_attrs(lo) & 1)
	   ? "Yes" : "No");

    desc = efi_loadopt_desc(lo, lo_len);
    printf("\n  Description: ");
    if (!desc)
	printf("<invalid description> ");
    else if (desc[0])
	printf("\"%s\" ", desc);

    efidp = efi_loadopt_path(lo, lo_len);
    pathlen = efi_loadopt_pathlen(lo, lo_len);

    printf("\n  Path: ");
    rc = efidp_format_device_path(NULL, 0, efidp, pathlen);
    if (rc < 0) {
	printf("<bad device path>");
	return;
    }
    text_path_len = rc + 1;
    text_path = alloca(text_path_len);
    if (!text_path) {
	fprintf(stderr, "MEMORY ALLOCATION FAILURE");
	return;
    }
    rc = efidp_format_device_path((char *)text_path,
				  text_path_len, efidp, pathlen);
    if (rc < 0) {
	printf("<bad device path>");
	return;
    }
    if (text_path && text_path_len >= 1)
	printf("%s", text_path);

}

/*
 * Print GUID using efivar library
 */
static void guid_printf(void *v_guid)
{
    efi_guid_t *guid = v_guid;
    char *guid_str = NULL;
    int rc;

    /* allocates a suitable string and populates it with string representation of a UEFI GUID. */
    rc = efi_guid_to_str(guid, &guid_str);
    if (rc < 0) {
        printf("<invalid guid>");
        return;
    }

    printf("%s", guid_str);
    free(guid_str);
}

/*
 * Print UC16 character string
 */
static void wchar_printf(int len, void *wchar)
{
    int i;
    uint16_t *ptr = wchar;

    /*
     * this is necessary because UEFI uses UC16, which is a two byte
     * wide char.  Most linux tools use UC32, which is a four byte
     * wide char, so we can't simply treat UEFI strings as arrays of
     * wchar_t
     */
    for (i = 0; i < len; i++) {
        wchar_t c = (wchar_t)ptr[i];
        printf("%lc", c);
    }
}

/*
 * Print the boot variable BootOrder to show a priority list of boot targets
 * From the UEFI spec: "The BootOrder variable contains an array of UINT16's
 * that make up an ordered list of the Boot####options."
 */
static void boot_order_printf(void *ev, uint64_t len)	/* FIXME make these all u32 */
{
    BYTE *buffer = ev;
    uint64_t l = len;
    uint64_t i;

    if (len % 2 != 0) {
        printf("<invalid boot order>");
        return;
    }

    printf("\n  Boot Order: ");

    for (i = 0; i < l; i+=2) {
        TPM_RC rc;
        uint16_t b;

        rc = TSS_UINT16LE_Unmarshal(&b, &buffer, (uint32_t*)&len);
        if (rc == TPM_RC_SUCCESS) {
            printf("Boot%04x ", b);
        } else {
            printf("<invalid data>");
            return;
        }
    }
}

/*
 * Print the boot variable SecureBoot as enabled or disabled
 * Caller function ensures there is at least 'len' bytes that are accessable
 * starting from 'ev'
 */
static void secure_boot_printf(uint8_t *ev, uint64_t len)
{
    printf("\n  Enabled: ");

    // Only len == 0 or 1 is valid
    if (len == 0) {
        printf("no");
    } else if (len > 1) {
        printf("<invalid secure boot>");
    } else {
        if (*ev == 0) {
            printf("no");
        }
        else {
            printf("yes");
        }
    }
}

/* This structure is used to designate the measurement of UEFI variables. The
   structure is defined in the TGC PC Client Platform Firmware Profile Specification
   Revision 1.04 Section 9.2.6.

   typedef struct tdUEFI_VARIABLE_DATA {
       uint8_t VariableName[16];
       uint64_t UnicodeNameLength;
       uint64_t VariableDataLength;
       uint8_t UnicodeName[];
       //uint8_t VariableData[]; // starts at UnicodeName + UnicodeNameLength*2
   } UEFI_VARIABLE_DATA;

   There are many types of UEFI variables - see UEFI spec for all different
   types. This only handles the BOOT####, SecureBoot, and BootOrder.
 */
static void variable_printf(void* ev, uint32_t eventSize, uint32_t eventType)	/* FIXME change frpm void */
{
    BYTE *buffer = ev;
    /*
     * UC16 string for "BootOrder". Note only one terminating zero
     * because string termination adds an extra one
     */
    const unsigned char bootorder[] =
        "\x42\x00\x6f\x00\x6f\x00\x74\x00\x4f\x00\x72\x00"
        "\x64\x00\x65\x00\x72";

    // UC16 string for "SecureBoot"
    const unsigned char secureboot[] =
        "\x53\x00\x65\x00\x63\x00\x75\x00\x72\x00\x65\x00"
        "\x42\x00\x6f\x00\x6f\x00\x74";

    int is_boot_order;
    int is_secure_boot;
    BYTE guid[16];
    TPM_RC rc;
    uint64_t unicodeNameLength;
    uint64_t variableDataLength;

    printf("  GUID: ");
    rc = TSS_Array_Unmarshalu(guid, sizeof(guid), &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        guid_printf(guid);
    } else {
        printf("<invalid data>");
    }
    /* FIXME falls through on error */
    printf("\n  VAR: ");
    rc = TSS_UINT64LE_Unmarshal(&unicodeNameLength, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        wchar_printf(unicodeNameLength, buffer+8);
    } else {
        printf("<invalid data>");
    }

    rc = TSS_UINT64LE_Unmarshal(&variableDataLength, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        is_boot_order = (unicodeNameLength*2 == sizeof(bootorder) &&
                         memcmp(buffer, bootorder, sizeof(bootorder)) == 0);
        is_secure_boot = (unicodeNameLength*2 == sizeof(secureboot) &&
                         memcmp(buffer, secureboot, sizeof(secureboot)) == 0);

        // Skip to UEFI_VARIABLE_DATA.VariableData
        buffer += unicodeNameLength*2;
        eventSize -= unicodeNameLength*2;

        if (variableDataLength > eventSize) {
            printf("<invalid data size>");
        } else {
            if (is_boot_order)
		/* FIXME cast safe because of above length check */
		boot_order_printf(buffer, (uint32_t)variableDataLength);
            else if (is_secure_boot)
                secure_boot_printf(buffer, variableDataLength);
            else if (eventType == EV_EFI_VARIABLE_BOOT)
                load_option_printf(buffer, variableDataLength);
        }
    }

    printf("\n");
}

/* This structure is used in measuring a PE/COFF image. It's defined in the TGC
   PC Client Platform Firmware Profile Specification Revision 1.04 Section 9.2.3.

   typedef uint64_t UEFI_PHYSICAL_ADDRESS;
   typedef struct tdUEFI_IMAGE_LOAD_EVENT {
       UEFI_PHYSICAL_ADDRESS ImageLocationInMemory;
       uint64_t ImageLengthInMemory;
       uint64_t ImageLinkTimeAddress;
       uint64_t LengthOfDevicePath;
       uint8_t DevicePath[];
   } UEFI_IMAGE_LOAD_EVENT;

 * Print loaded UEFI image information
 */
static void image_load_printf(void *ev, uint32_t eventSize)
{
    BYTE *buffer = ev;
    uint64_t imageLocationInMemory;
    uint64_t imageLengthInMemory;
    uint64_t imageLinkTimeAddress;
    uint64_t lengthOfDevicePath;
    int text_path_len, ret;
    unsigned char *text_path;
    TPM_RC rc;

    printf("  Image location in memory: ");
    rc = TSS_UINT64LE_Unmarshal(&imageLocationInMemory, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("0x%" PRIx64 "\n", imageLocationInMemory);
    } else {
        printf("<invalid data>\n");
    }
    /* FIXME fall throyugh issue */
    printf("  Image length in memory: ");
    rc = TSS_UINT64LE_Unmarshal(&imageLengthInMemory, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("%" PRIu64 "\n", imageLengthInMemory);
    } else {
        printf("<invalid data>\n");
    }

    printf("  Image link time address: ");
    rc = TSS_UINT64LE_Unmarshal(&imageLinkTimeAddress, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("0x%" PRIx64 "\n", imageLinkTimeAddress);
    } else {
        printf("<invalid data>\n");
    }

    printf("  Path: ");
    rc = TSS_UINT64LE_Unmarshal(&lengthOfDevicePath, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
	/* FIXME check eventSize vs lengthOfDevicePath */
	/* FIXME comment return meaning */
	/* NULL to get get length */
        ret = efidp_format_device_path(NULL, 0, (const_efidp)buffer,
                                       lengthOfDevicePath);
        if (ret < 0) {
            printf("<bad device path>\n");
            return;
        }
        text_path_len = ret + 1;	/* FIXME add nul terminator */
        text_path = alloca(text_path_len);
        if (!text_path) {		/* FIXME if text_path == NULL */
            printf("<alloca() failed\n>");
            return;
        }
	ret = efidp_format_device_path((char *)text_path,
                                       text_path_len,
                                       (const_efidp)buffer,
                                       lengthOfDevicePath);
        if (ret < 0) {
            printf("<bad device path>\n");
            return;
        }
	/* FIXME isnt text_path_len always >= 1 ? */
        if (text_path && text_path_len >= 1)	/* FIXME text_path != NULL */
            printf("%s\n", text_path);
    } else {
        printf("<bad device length>\n");
    }
}

/* This structure contains a GUID Partition Table, and is defined in the TGC PC
   Client Platform Firmware Profile Specification Revision 1.04 Section 9.4.
   Its structure members are defined in the UEFI Specification Version 2.8
   Section 5.3

   typedef struct tdUEFI_PARTITION_TABLE_HEADER {
       uint64_t Signature;
       uint32_t Revision;
       uint32_t HeaderSize;
       uint32_t HeaderCRD32;
       uint32_t Reserved;
       uint64_t MyLBA;
       uint64_t AlternateLBA;
       uint64_t FirstUsableLBA;
       uint64_t LastUsableLBA;
       uint8_t DiskGUID[16];
       uint64_t PartitionEntryLBA;
       uint32_t NumberOfPartitionEntries;
       uint32_t SizeOfPartitionEntry;
       uint32_t PartitionEntryArrayCRC32;
   } UEFI_PARTITION_TABLE_HEADER;
   
   typedef struct tdUEFI_PARTITION_ENTRY {
       uint8_t PartitionTypeGUID[16];
       uint8_t UniquePartitionGUID[16];
       uint64_t StartingLBA;
       uint64_t EndingLBA;
       uint64_t Attributes;
       uint8_t PartitionName[72];
   } UEFI_PARTITION_ENTRY;
   
   typedef struct tdUEFI_GPT_DATA {
       UEFI_PARTITION_TABLE_HEADER UEFIPartitionHeader;
       uint64_t NumberOfPartitions;
       UEFI_PARTITION_ENTRY Partitions[];
   } UEFI_GPT_DATA;

   Print Guid Partition Table (GPT) information
 */
static void gpt_printf(void *ev, uint32_t eventSize) {
    BYTE *buffer = ev;
    BYTE guid[16];
    uint64_t firstUsableLBA, lastUsableLBA, numberOfPartitions;
    uint64_t i, startingLBA, endingLBA;
    TPM_RC rc;

    // Skip to UEFI_PARTITION_TABLE_HEADER.FirstUsableLBA
    buffer += 40;
    eventSize -= 40;		/* FIXME test for safety before subtract */

    printf("  Starting LBA: ");
    rc = TSS_UINT64LE_Unmarshal(&firstUsableLBA, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("0x%016" PRIx64 "\n", firstUsableLBA);
    } else {
        printf("<invalid data>\n");
    }
    /* FIXME fall through on error */
    printf("  Ending LBA: ");
    rc = TSS_UINT64LE_Unmarshal(&lastUsableLBA, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("0x%016" PRIx64 "\n", lastUsableLBA);
    } else {
        printf("<invalid data>\n");
    }

    // Skip to UEFI_GPT_DATA.NumberOfPartitions
    buffer += 36;	/* FIXME comment */
    eventSize -= 36;	/* FIXME range check */

    printf("  Number of Partitions: ");
    rc = TSS_UINT64LE_Unmarshal(&numberOfPartitions, &buffer, &eventSize);
    if (rc == TPM_RC_SUCCESS) {
        printf("%" PRIx64 "\n", numberOfPartitions);
    } else {
        printf("<invalid data>\n");
    }
    /* FIXME fall through */
    for (i = 0; i < numberOfPartitions; i++) {
        // Skip to UEFI_PARTITION_ENTRY.UniquePartitionGUID
        buffer += 16;	/* FIXME range check */
        eventSize -= 16;

        printf("    ");
        rc = TSS_Array_Unmarshalu(guid, sizeof(guid), &buffer, &eventSize);
        if (rc == TPM_RC_SUCCESS) {
            guid_printf(guid);
        } else {
            printf("<invalid data>");
        }

        printf(": Starting LBA: ");
        rc = TSS_UINT64LE_Unmarshal(&startingLBA, &buffer, &eventSize);
        if (rc == TPM_RC_SUCCESS) {
            printf("0x%016" PRIx64 , startingLBA);
        } else {
            printf("<invalid data>");
        }

        printf(", Ending LBA: ");
        rc = TSS_UINT64LE_Unmarshal(&endingLBA, &buffer, &eventSize);
        if (rc == TPM_RC_SUCCESS) {
            printf("0x%016" PRIx64 "\n", endingLBA);
        } else {
            printf("<invalid data>\n");
        }

        // Skip to the next UEFI_PARTITION_ENTRY
        buffer += 80;	/* FIXME range check ??? */
        eventSize -= 16;
    }
}
#endif

void TSS_EVENT2_Line_Trace(TCG_PCR_EVENT2 *event)
{
    uint32_t rc = 0;
    uint32_t count;
    uint16_t digestSize;
    TSST_EFIData *efiData = NULL;
    printf("TSS_EVENT2_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    printf("TSS_EVENT2_Line_Trace: digest count %u\n", event->digests.count);
    for (count = 0 ; count < event->digests.count ; count++) {
	printf("TSS_EVENT2_Line_Trace: digest %u algorithm %04x\n",
	       count, event->digests.digests[count].hashAlg);
	digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	TSS_PrintAll("TSS_EVENT2_Line_Trace: PCR",
		     (uint8_t *)&event->digests.digests[count].digest, digestSize);
    }
    TSS_PrintAll("TSS_EVENT2_Line_Trace: event",
		 event->event, event->eventSize);

    /* FIXME this will eventually replace all the hard coded events */
    if (rc == 0) {
	rc = TSS_EFIData_Init(&efiData, event->eventType);
    }
    if (rc == 0) {
	rc = TSS_EFIData_ReadBuffer(efiData, event->event, event->eventSize, event->pcrIndex);
    }
    if (rc == 0) {
       TSS_EFIData_Trace(efiData);
    }
    TSS_EFIData_Free(efiData);
    /* FIXME end new code */
#if 0	/* obsolete code, to be  removed */
    switch (event->eventType) {
    case EV_IPL:
    case EV_EFI_ACTION: {
      /*
       * Grub places standard ASCII strings for the boot log in
       * EV_IPL and EV_ACTION events, so print them here
       */
	printf("  Event: \"%.*s\"\n", event->eventSize, event->event);
	break;
    }
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
	if (event->eventSize != 16)
	    break;
	printf("  Base: 0x%lx\n  Length: 0x%lx\n",
	       *((unsigned long *)event->event),
	       *((unsigned long *)(event->event + 8)));
	break;
#ifdef HAVE_EFIBOOT_H
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_EFI_VARIABLE_BOOT: {
        variable_printf(event->event, event->eventSize, event->eventType);
        break;
    }
    case EV_EFI_BOOT_SERVICES_APPLICATION:
    case EV_EFI_BOOT_SERVICES_DRIVER:
    case EV_EFI_RUNTIME_SERVICES_DRIVER: {
        image_load_printf(event->event, event->eventSize);
        break;
    }
    case EV_EFI_GPT_EVENT: {
        gpt_printf(event->event, event->eventSize);
        break;
    }
#endif
    default:
	break;
    }
#endif
    return;
}

/* tables to map eventType to text */

typedef struct {
    uint32_t eventType;
    const char *text;
} EVENT_TYPE_TABLE;

const EVENT_TYPE_TABLE eventTypeTable [] = {
    {EV_PREBOOT_CERT, "EV_PREBOOT_CERT"},
    {EV_POST_CODE, "EV_POST_CODE"},
    {EV_UNUSED, "EV_UNUSED"},
    {EV_NO_ACTION, "EV_NO_ACTION"},
    {EV_SEPARATOR, "EV_SEPARATOR"},
    {EV_ACTION, "EV_ACTION"},
    {EV_EVENT_TAG, "EV_EVENT_TAG"},
    {EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS"},
    {EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION"},
    {EV_CPU_MICROCODE, "EV_CPU_MICROCODE"},
    {EV_PLATFORM_CONFIG_FLAGS, "EV_PLATFORM_CONFIG_FLAGS"},
    {EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES"},
    {EV_COMPACT_HASH, "EV_COMPACT_HASH"},
    {EV_IPL, "EV_IPL"},
    {EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA"},
    {EV_NONHOST_CODE, "EV_NONHOST_CODE"},
    {EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG"},
    {EV_NONHOST_INFO, "EV_NONHOST_INFO"},
    {EV_OMIT_BOOT_DEVICE_EVENTS, "EV_OMIT_BOOT_DEVICE_EVENTS"},
    {EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE"},
    {EV_EFI_VARIABLE_DRIVER_CONFIG, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
    {EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT"},
    {EV_EFI_BOOT_SERVICES_APPLICATION, "EV_EFI_BOOT_SERVICES_APPLICATION"},
    {EV_EFI_BOOT_SERVICES_DRIVER, "EV_EFI_BOOT_SERVICES_DRIVER"},
    {EV_EFI_RUNTIME_SERVICES_DRIVER, "EV_EFI_RUNTIME_SERVICES_DRIVER"},
    {EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT"},
    {EV_EFI_ACTION, "EV_EFI_ACTION"},
    {EV_EFI_PLATFORM_FIRMWARE_BLOB, "EV_EFI_PLATFORM_FIRMWARE_BLOB"},
    {EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES"},
    {EV_EFI_HCRTM_EVENT, "EV_EFI_HCRTM_EVENT"},
    {EV_EFI_VARIABLE_AUTHORITY, "EV_EFI_VARIABLE_AUTHORITY"}
};

static void TSS_EVENT_EventType_Trace(uint32_t eventType)
{
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    printf("TSS_EVENT_EventType_Trace: %08x %s\n",
		   eventTypeTable[i].eventType, eventTypeTable[i].text);
	    return;
	}
    }
    printf("TSS_EVENT_EventType_Trace: %08x Unknown\n", eventType);
    return;
}

const char *TSS_EVENT_EventTypeToString(uint32_t eventType)
{
    const char *crc = NULL;
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    crc = eventTypeTable[i].text;
	}
    }
    if (crc == NULL) {
	crc = "Unknown event type";
    }
    return crc;
}

/*
 * TSS_TPML_DIGEST_VALUES_LE_Unmarshalu() Unmarshals TPML_DIGEST_VALUES struct
 * from a LE buffer into HBO data structure. This is similar to
 * TSS_TPML_DIGEST_VALUES_Unmarshalu but it unrmarshals TPML_DIGEST_VALUES's
 * count  and the digests array members from LE instead of HBO.
 */

static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32LE_Unmarshal(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > HASH_COUNT) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMT_HA_LE_Unmarshalu(&target->digests[i], buffer, size, NO);
    }
    return rc;
}

/*
 * TSS_TPMT_HA_LE_Unmarshalu() Unmarshals a TPMT_HA data from LE to HBO. This is
 * similar to TSS_TPMT_HA_Unmarshalu but differs specificaly for unmarshalling
 * hashAlg member from LE instead of from HBO.
 */
static TPM_RC
TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_LE_Unmarshalu(&target->hashAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_HA_Unmarshalu(&target->digest, buffer, size, target->hashAlg);
    }
    return rc;
}

/*
 * TSS_TPMI_ALG_HASH_LE_Unmarshalu() Unmarshals TPMI_ALG_HASH from a LE buffer
 * into HBO data structure. This is similar to TSS_TPMI_ALG_HASH_Unmarshalu but
 * unmarshals TPMI_ALG_HASH from LE instead of HBO.
 */
static TPM_RC
TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_LE_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/*
 * TSS_TPM_ALG_ID_LE_Unmarshalu() Unrmarshals TPM_ALG_ID from LE buffer. This is
 * simlar to TSS_TPM_ALG_ID_Unmarshalu but unmarshals from LE instead of HBO.
 */
static TPM_RC
TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target, BYTE **buffer,
                                 uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16LE_Unmarshal(target, buffer, size);
    }
    return rc;
}

/* TSS_TPML_DIGEST_VALUES_LE_Marshalu() Similar to TSS_TPML_DIGEST_VALUES_Marshalu
 * for TSS EVENT2 this marshals count to buffer in LE endianess.
 */
static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
                                       uint16_t *written, BYTE **buffer,
                                       uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMT_HA_LE_Marshalu(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* TSS_TPMT_HA_LE_Marshalu() Similar to TSS_TPMT_HA_Marshalu for TSS EVENT2,
 * this saves hashAlg attr as little endian into buffer.
 */
static TPM_RC
TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
			BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16LE_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_HA_Marshalu(&source->digest, written, buffer, size,
                                  source->hashAlg);
    }
    return rc;
}

/*
 * TSS_UINT32LE_Marshal() Marshals uint32_t from HBO into LE in the given buffer.
 */
TPM_RC
TSS_UINT32LE_Marshal(const UINT32 *source, uint16_t *written, BYTE **buffer,
                 uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint32_t))) {
            (*buffer)[0] = (BYTE)((*source >> 0) &  0xff);
            (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);
            (*buffer)[2] = (BYTE)((*source >> 16) & 0xff);
            (*buffer)[3] = (BYTE)((*source >> 24) & 0xff);

            *buffer += sizeof(uint32_t);
            if (size != NULL) {
                *size -= sizeof(uint32_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint32_t);
    return rc;
}

/*
 * UINT16LE_Marshal() Marshals uint16_t from HBO into LE in the given buffer.
 */

TPM_RC
TSS_UINT16LE_Marshalu(const UINT16 *source, uint16_t *written, BYTE **buffer,
                      uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint16_t))) {
	    (*buffer)[0] = (BYTE)((*source >> 0) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);

            *buffer += sizeof(uint16_t);

            if (size != NULL) {
                *size -= sizeof(uint16_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint16_t);
    return rc;
}
