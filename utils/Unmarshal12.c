/********************************************************************************/
/*										*/
/*			     Parameter Unmarshaling				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Unmarshal12.c 1157 2018-04-17 14:09:56Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017					*/
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

#include <string.h>

#include <tss2/Unmarshal_fp.h>
#include <tss2/tpmconstants12.h>
#include <tss2/Unmarshal12_fp.h>

TPM_RC
TSS_TPM_STARTUP_TYPE_Unmarshal(TPM_STARTUP_TYPE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshal(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_ST_CLEAR:
	  case TPM_ST_STATE:
	  case TPM_ST_DEACTIVATED:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* 5.0 */


TPM_RC
TSS_TPM_VERSION_Unmarshal(TPM_VERSION *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->major, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->minor, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->revMajor, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->revMinor, buffer, size);
    }
    return rc;
}

/* 6.0 */

TPM_RC
TSS_TPM_TAG_Unmarshal(TPM_TAG *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshal(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_TAG_RSP_COMMAND:
	  case TPM_TAG_RSP_AUTH1_COMMAND:
	  case TPM_TAG_RSP_AUTH2_COMMAND:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
 
/* 8.0 */

TPM_RC
TSS_TPM_PCR_SELECTION_Unmarshal(TPM_PCR_SELECTION *target, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->sizeOfSelect, buffer, size);   
    }
    if (rc == 0) {
	if (target->sizeOfSelect > sizeof(target->pcrSelect)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->pcrSelect, target->sizeOfSelect, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPM_PCR_INFO_LONG_Unmarshal(TPM_PCR_INFO_LONG *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t sizeRead32;
    uint32_t startSize;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&sizeRead32, buffer, size);
    }
    if (rc == 0) {
	if (sizeRead32 == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	startSize = *size;
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_LONG_Unmarshal(target, buffer, size);
    }
    if (rc == 0) {
	if (sizeRead32 != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_LONG_Unmarshal(TPM_PCR_INFO_LONG *target, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->localityAtCreation, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->localityAtRelease, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Unmarshal(&target->creationPCRSelection, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Unmarshal(&target->releasePCRSelection, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->digestAtCreation, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->digestAtRelease, SHA1_DIGEST_SIZE, buffer, size); 
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_SHORT_Unmarshal(TPM_PCR_INFO_SHORT *target, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Unmarshal(&target->pcrSelection, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->localityAtRelease, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->digestAtRelease, SHA1_DIGEST_SIZE, buffer, size); 
    }
    return rc;
}

/* 9.0 */

TPM_RC
TSS_TPM_SYMMETRIC_KEY_Unmarshal(TPM_SYMMETRIC_KEY *target, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->algId, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->encScheme, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->size, buffer, size);
    }
    if (rc == 0) {
	if (target->size > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->data, target->size, buffer, size); 
    }
    return rc;
}

/* 10.0 */

TPM_RC
TSS_TPM_RSA_KEY_PARMS_Unmarshal(TPM_RSA_KEY_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->keyLength, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->numPrimes, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->exponentSize, buffer, size);
    }
    if (rc == 0) {
	if (target->exponentSize > sizeof(target->exponent)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->exponent, target->exponentSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMU_PARMS_Unmarshal(TPMU_PARMS *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_ALG_RSA:		/* A structure of type TPM_RSA_KEY_PARMS */
	rc = TSS_TPM_RSA_KEY_PARMS_Unmarshal(&target->rsaParms, buffer, size);
	break;
      case TPM_ALG_AES128:	/* A structure of type TPM_SYMMETRIC_KEY_PARMS */
	/* not implemented yet */
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPMU_PARMS_Unmarshal(TPMU_PARMS *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    uint32_t sizeRead32;
    uint32_t startSize;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&sizeRead32, buffer, size);
    }
    if (rc == 0) {
	if (sizeRead32 == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	startSize = *size;
    }
    if (rc == 0) {
	rc = TSS_TPMU_PARMS_Unmarshal(target, buffer, size, selector);
    }
    if (rc == 0) {
	if (sizeRead32 != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}

TPM_RC
TSS_TPM_KEY_PARMS_Unmarshal(TPM_KEY_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->algorithmID, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->encScheme, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->sigScheme, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPMU_PARMS_Unmarshal(&target->parms, buffer, size, target->algorithmID);	
    }
    return rc;
}

TPM_RC
TSS_TPM_KEY12_Unmarshal(TPM_KEY12 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->fill, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->keyUsage, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->keyFlags, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->authDataUsage, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Unmarshal(&target->algorithmParms, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPM_PCR_INFO_LONG_Unmarshal(&target->PCRInfo, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Unmarshal(&target->pubKey, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Unmarshal(&target->encData, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_STORE_PUBKEY_Unmarshal(TPM_STORE_PUBKEY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->keyLength, buffer, size);
    }
    if (rc == 0) {
	if (target->keyLength > sizeof(target->key)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->key, target->keyLength, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_PUBKEY_Unmarshal(TPM_PUBKEY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Unmarshal(&target->algorithmParms, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Unmarshal(&target->pubKey, buffer, size);
    }
    return rc;
}

/* 19 */

TPM_RC
TSS_TPM_NV_ATTRIBUTES_Unmarshal(TPM_NV_ATTRIBUTES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->attributes, buffer, size);                      
    }
    return rc;
}

TPM_RC
TSS_TPM_NV_DATA_PUBLIC_Unmarshal(TPM_NV_DATA_PUBLIC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->nvIndex, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshal(&target->pcrInfoRead, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshal(&target->pcrInfoWrite, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_NV_ATTRIBUTES_Unmarshal(&target->permission, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->bReadSTClear, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->bWriteSTClear, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->bWriteDefine, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->dataSize, buffer, size);                      
    }
    return rc;
}						  

/* 21 */

TPM_RC
TSS_TPM_CAP_VERSION_INFO_Unmarshal(TPM_CAP_VERSION_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_VERSION_Unmarshal(&target->version, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->specLevel, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->errataRev, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->tpmVendorID, sizeof(target->tpmVendorID), buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->vendorSpecificSize, buffer, size);
    }
    if (rc == 0) {
	if (target->vendorSpecificSize > sizeof(target->vendorSpecific)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->vendorSpecific, target->vendorSpecificSize, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_DA_INFO_Unmarshal(TPM_DA_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->state, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->currentCount, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->thresholdCount, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_DA_ACTION_TYPE_Unmarshal(&target->actionAtThreshold, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->actionDependValue, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->vendorDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->vendorDataSize > sizeof(target->vendorData)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->vendorData, target->vendorDataSize , buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_DA_INFO_LIMITED_Unmarshal(TPM_DA_INFO_LIMITED *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshal(&target->state, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_DA_ACTION_TYPE_Unmarshal(&target->actionAtThreshold, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->vendorDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->vendorDataSize > sizeof(target->vendorData)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->vendorData, target->vendorDataSize , buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_DA_ACTION_TYPE_Unmarshal(TPM_DA_ACTION_TYPE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshal(&target->tag, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->actions, buffer, size);
    }
    return rc;
}
