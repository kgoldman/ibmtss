/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal12.c 1193 2018-05-01 20:55:39Z kgoldman $		*/
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

#ifdef TPM_TPM12

#include <string.h>

#include <tss2/tssmarshal.h>
#include <tss2/tsserror.h>
#include <tss2/tssprint.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/Unmarshal12_fp.h>
#include <tss2/tssmarshal12.h>

/* The marshaling functions are slightly different from the TPM side.  The TPM assumes that all
   structures are trusted, and so has no error checking.  The TSS side makes no such assumption.

   The prototype pattern is:

   Return:

   An extra return code, TSS_RC_INSUFFICIENT_BUFFER, indicates that the supplied buffer size is too
   small.  The TPM functions assert.

   'source' is the structure to be marshaled, the same as the TPM functions.
   'written' is the __additional__ number of bytes written, the value that the TPM returns.
   'buffer' is the buffer written, the same as the TPM functions.
   ' size' is the remaining size of the buffer, the same as the TPM functions.

   If 'buffer' is NULL, 'written' is updated but no marshaling is performed.  This is used in a two
   pass pattern, where the first pass returns the size of the buffer to be malloc'ed.

   If 'size' is NULL, the source is unmarshaled without a size check.  The caller must ensure that
   the buffer is sufficient, often due to a malloc after the first pass.  */

/*Unmarshal
  Command parameter marshaling
*/

TPM_RC
TSS_ActivateIdentity_In_Marshal(const ActivateIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->idKeyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->blobSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->blob, source->blobSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_CreateEndorsementKeyPair_In_Marshal(const CreateEndorsementKeyPair_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_Array_Marshal(source->antiReplay, TPM_NONCE_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshal(&source->keyInfo, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_CreateWrapKey_In_Marshal(const CreateWrapKey_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->dataUsageAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->dataMigrationAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshal(&source->keyInfo, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Extend_In_Marshal(const Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->pcrNum, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->inDigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_FlushSpecific_In_Marshal(const FlushSpecific_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->resourceType, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_GetCapability12_In_Marshal(const GetCapability12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->capArea, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->subCapSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->subCap, source->subCapSize, written, buffer, size);	
    }
    return rc;
}						  

TPM_RC
TSS_LoadKey2_In_Marshal(const LoadKey2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshal(&source->inKey, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_MakeIdentity_In_Marshal(const MakeIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->identityAuth, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->labelPrivCADigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshal(&source->idKeyParams, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_DefineSpace12_In_Marshal(const NV_DefineSpace12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_NV_DATA_PUBLIC_Marshal(&source->pubInfo, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->encAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValueAuth_In_Marshal(const NV_ReadValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValue_In_Marshal(const NV_ReadValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_WriteValue_In_Marshal(const NV_WriteValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->dataSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->data, source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_WriteValueAuth_In_Marshal(const NV_WriteValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->dataSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->data, source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_OwnerReadInternalPub_In_Marshal(const OwnerReadInternalPub_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyHandle, written, buffer, size);
    }
    return rc;
}						  
 
TPM_RC
TSS_OwnerSetDisable_In_Marshal(const OwnerSetDisable_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->disableState, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OSAP_In_Marshal(const OSAP_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->entityType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->entityValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->nonceOddOSAP, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    return rc;
}						  
 
TPM_RC
TSS_PcrRead12_In_Marshal(const PcrRead12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->pcrIndex, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_PCR_Reset12_In_Marshal(const PCR_Reset12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
    	rc = TSS_TPM_PCR_SELECTION_Marshal(&source->pcrSelection, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Quote2_In_Marshal(const Quote2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->externalData, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_PCR_SELECTION_Marshal(&source->targetPCR, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->addVersion, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_ReadPubek_In_Marshal(const ReadPubek_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->antiReplay, TPM_NONCE_SIZE, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Sign12_In_Marshal(const Sign12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->areaToSignSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->areaToSign, source->areaToSignSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_Startup12_In_Marshal(const Startup12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_STARTUP_TYPE_Marshal(&source->startupType, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TakeOwnership_In_Marshal(const TakeOwnership_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->protocolID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->encOwnerAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->encOwnerAuth, source->encOwnerAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->encSrkAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->encSrkAuth, source->encSrkAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshal(&source->srkParams, written, buffer, size);
    }
    return rc;
}

/*
  Response parameter unmarshaling
*/

TPM_RC
TSS_ActivateIdentity_Out_Unmarshal(ActivateIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_SYMMETRIC_KEY_Unmarshal(&target->symmetricKey, buffer, size);
    } 
    return rc;
}

TPM_RC
TSS_CreateEndorsementKeyPair_Out_Unmarshal(CreateEndorsementKeyPair_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_PUBKEY_Unmarshal(&target->pubEndorsementKey, buffer, size);
    } 
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->checksum, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_CreateWrapKey_Out_Unmarshal(CreateWrapKey_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_KEY12_Unmarshal(&target->wrappedKey, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Extend_Out_Unmarshal(Extend_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->outDigest, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_GetCapability12_Out_Unmarshal(GetCapability12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->respSize, buffer, size);
    }
    if (rc == 0) {
	if (target->respSize > sizeof(target->resp)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->resp, target->respSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_LoadKey2_Out_Unmarshal(LoadKey2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->inkeyHandle, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_MakeIdentity_Out_Unmarshal(MakeIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshal(&target->idKey, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->identityBindingSize, buffer, size);
    }
    if (rc == 0) {
	if (target->identityBindingSize > sizeof(target->identityBinding)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->identityBinding, target->identityBindingSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValueAuth_Out_Unmarshal(NV_ReadValueAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->dataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->data, target->dataSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValue_Out_Unmarshal(NV_ReadValue_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->dataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->data, target->dataSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OIAP_Out_Unmarshal(OIAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->authHandle, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->nonceEven, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OSAP_Out_Unmarshal(OSAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->authHandle, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->nonceEven, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->nonceEvenOSAP, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OwnerReadInternalPub_Out_Unmarshal(OwnerReadInternalPub_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_PUBKEY_Unmarshal(&target->publicPortion, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_PcrRead12_Out_Unmarshal(PcrRead12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->outDigest, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Quote2_Out_Unmarshal(Quote2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshal(&target->pcrData, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->versionInfoSize, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_CAP_VERSION_INFO_Unmarshal(&target->versionInfo, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->sigSize, buffer, size);
    }
    if (rc == 0) {
	if (target->sigSize > sizeof(target->sig)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->sig, target->sigSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Sign12_Out_Unmarshal(Sign12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshal(&target->sigSize, buffer, size);
    }
    if (rc == 0) {
	if (target->sigSize > sizeof(target->sig)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->sig, target->sigSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_ReadPubek_Out_Unmarshal(ReadPubek_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_PUBKEY_Unmarshal(&target->pubEndorsementKey, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshal(target->checksum, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TakeOwnership_Out_Unmarshal(TakeOwnership_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshal(&target->srkPub, buffer, size);
    }
    return rc;
}

/*
  Structure marshaling
*/

TPM_RC
TSS_TPM_STARTUP_TYPE_Marshal(const TPM_STARTUP_TYPE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* 5.0 */


TPM_RC
TSS_TPM_VERSION_Marshal(const TPM_VERSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->major, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->minor, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->revMajor, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->revMinor, written, buffer, size);
    }
    return rc;
}

/* 8.0 */

TPM_RC
TSS_TPM_PCR_SELECTION_Marshal(const TPM_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->sizeOfSelect, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->pcrSelect, source->sizeOfSelect, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_LONG_Marshal(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_PCR_INFO_LONG;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->localityAtCreation, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->localityAtRelease, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshal(&source->creationPCRSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshal(&source->releasePCRSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->digestAtCreation, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->digestAtRelease, SHA1_DIGEST_SIZE, written, buffer, size); 
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_SHORT_Marshal(const TPM_PCR_INFO_SHORT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshal(&source->pcrSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->localityAtRelease, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->digestAtRelease, SHA1_DIGEST_SIZE, written, buffer, size); 
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPM_PCR_INFO_LONG_Marshal(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint32_t);	/* skip size */
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_LONG_Marshal(source, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	uint32_t sizeWritten32 = sizeWritten;	/* back fill size */
	if (buffer != NULL) {
	    rc = TSS_UINT32_Marshal(&sizeWritten32, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint32_t);
	}
    }
    return rc;
}

/* 9.0 */

TPM_RC
TSS_TPM_SYMMETRIC_KEY_Marshal(const TPM_SYMMETRIC_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->algId, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->encScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->data, source->size, written, buffer, size);
    }
    return rc;
}

/* 10.0 */

TPM_RC
TSS_TPM_RSA_KEY_PARMS_Marshal(const TPM_RSA_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyLength, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->numPrimes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->exponentSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->exponent, source->exponentSize, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMU_PARMS_Marshal(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_ALG_RSA:		/* A structure of type TPM_RSA_KEY_PARMS */
	rc = TSS_TPM_RSA_KEY_PARMS_Marshal(&source->rsaParms, written, buffer, size);
	break;
      case TPM_ALG_AES128:	/* A structure of type TPM_SYMMETRIC_KEY_PARMS */
	/* not implemented yet */
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPMU_PARMS_Marshal(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint32_t);	/* skip size */
    }
    if (rc == 0) {
	rc = TSS_TPMU_PARMS_Marshal(source, &sizeWritten, buffer, size, selector);
    }
    if (rc == 0) {
	*written += sizeWritten;
	uint32_t sizeWritten32 = sizeWritten;	/* back fill size */
	if (buffer != NULL) {
	    rc = TSS_UINT32_Marshal(&sizeWritten32, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint32_t);
	}
    }
    return rc;
}

TPM_RC
TSS_TPM_KEY_PARMS_Marshal(const TPM_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->algorithmID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->encScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->sigScheme, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPMU_PARMS_Marshal(&source->parms, written, buffer, size, source->algorithmID);	
    }
    return rc;
}

TPM_RC
TSS_TPM_STORE_PUBKEY_Marshal(const TPM_STORE_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyLength, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->key, source->keyLength, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_KEY12_PUBKEY_Marshal(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshal(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshal(&source->pubKey, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_PUBKEY_Marshal(const TPM_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshal(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshal(&source->pubKey, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_KEY12_Marshal(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_KEY12;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	uint16_t fill = 0;
	rc = TSS_UINT16_Marshal(&fill, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->keyUsage, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->keyFlags, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->authDataUsage, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshal(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPM_PCR_INFO_LONG_Marshal(&source->PCRInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshal(&source->pubKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshal(&source->encData, written, buffer, size);
    }
    return rc;
}

/* 11.0 */

TPM_RC
TSS_TPM_QUOTE_INFO2_Marshal(const TPM_QUOTE_INFO2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_QUOTE_INFO2;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->fixed, 4, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->externalData, TPM_NONCE_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshal(&source->infoShort, written, buffer, size);;
    }
    return rc;
}

/* 12.0 */

TPM_RC
TSS_TPM_EK_BLOB_Marshal(const TPM_EK_BLOB *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_EK_BLOB;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->ekType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->blobSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->blob, source->blobSize, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_EK_BLOB_ACTIVATE_Marshal(const TPM_EK_BLOB_ACTIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_EK_BLOB_ACTIVATE;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_SYMMETRIC_KEY_Marshal(&source->sessionKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->idDigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshal(&source->pcrInfo, written, buffer, size);
    }
    return rc;
}

/* 19.0 */

TPM_RC
TSS_TPM_NV_ATTRIBUTES_Marshal(const TPM_NV_ATTRIBUTES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0; 
    if (rc == 0) {
	uint16_t tag = TPM_TAG_NV_ATTRIBUTES;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->attributes, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_NV_DATA_PUBLIC_Marshal(const TPM_NV_DATA_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_NV_DATA_PUBLIC;
	rc = TSS_UINT16_Marshal(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshal(&source->pcrInfoRead, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshal(&source->pcrInfoWrite, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_NV_ATTRIBUTES_Marshal(&source->permission, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->bReadSTClear, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->bWriteSTClear, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->bWriteDefine, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->dataSize, written, buffer, size);
    }
    return rc;
}

/* 21.0 */

TPM_RC
TSS_TPM_CAP_VERSION_INFO_Marshal(const TPM_CAP_VERSION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_VERSION_Marshal(&source->version, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->specLevel, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->errataRev, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->tpmVendorID, 4, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->vendorSpecificSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->vendorSpecific, source->vendorSpecificSize, written, buffer, size);
    }
    return rc;
} ;

#endif		/* TPM_TPM12 */
