/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal12.h 1189 2018-05-01 13:27:40Z kgoldman $		*/
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

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that have to marshal / unmarshal
   structures for file save / load.
*/

#ifndef TSSMARSHAL12_H
#define TSSMARSHAL12_H

#include "BaseTypes.h"
#include <tss2/TPM_Types.h>

#include <tss2/Parameters12.h>
#include <tss2/tpmstructures12.h>

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC
    TSS_ActivateIdentity_In_Marshal(const ActivateIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateEndorsementKeyPair_In_Marshal(const CreateEndorsementKeyPair_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateWrapKey_In_Marshal(const CreateWrapKey_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Extend_In_Marshal(const Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_FlushSpecific_In_Marshal(const FlushSpecific_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability12_In_Marshal(const GetCapability12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadKey2_In_Marshal(const LoadKey2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeIdentity_In_Marshal(const MakeIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_DefineSpace12_In_Marshal(const NV_DefineSpace12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValueAuth_In_Marshal(const NV_ReadValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValue_In_Marshal(const NV_ReadValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_WriteValue_In_Marshal(const NV_WriteValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_WriteValueAuth_In_Marshal(const NV_WriteValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerReadInternalPub_In_Marshal(const OwnerReadInternalPub_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerSetDisable_In_Marshal(const OwnerSetDisable_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OSAP_In_Marshal(const OSAP_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PcrRead12_In_Marshal(const PcrRead12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Reset12_In_Marshal(const PCR_Reset12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote2_In_Marshal(const Quote2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPubek_In_Marshal(const ReadPubek_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign12_In_Marshal(const Sign12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Startup12_In_Marshal(const Startup12_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TakeOwnership_In_Marshal(const TakeOwnership_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_ActivateIdentity_Out_Unmarshal(ActivateIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateEndorsementKeyPair_Out_Unmarshal(CreateEndorsementKeyPair_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateWrapKey_Out_Unmarshal(CreateWrapKey_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Extend_Out_Unmarshal(Extend_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability12_Out_Unmarshal(GetCapability12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadKey2_Out_Unmarshal(LoadKey2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeIdentity_Out_Unmarshal(MakeIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValueAuth_Out_Unmarshal(NV_ReadValueAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValue_Out_Unmarshal(NV_ReadValue_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OIAP_Out_Unmarshal(OIAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OSAP_Out_Unmarshal(OSAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerReadInternalPub_Out_Unmarshal(OwnerReadInternalPub_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PcrRead12_Out_Unmarshal(PcrRead12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote2_Out_Unmarshal(Quote2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPubek_Out_Unmarshal(ReadPubek_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign12_Out_Unmarshal(Sign12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TakeOwnership_Out_Unmarshal(TakeOwnership_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_STARTUP_TYPE_Marshal(const TPM_STARTUP_TYPE *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_VERSION_Marshal(const TPM_VERSION*source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_PCR_SELECTION_Marshal(const TPM_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_SHORT_Marshal(const TPM_PCR_INFO_SHORT *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM4B_TPM_PCR_INFO_LONG_Marshal(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_LONG_Marshal(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_SYMMETRIC_KEY_Marshal(const TPM_SYMMETRIC_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_RSA_KEY_PARMS_Marshal(const TPM_RSA_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPMU_PARMS_Marshal(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM4B_TPMU_PARMS_Marshal(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM_KEY_PARMS_Marshal(const TPM_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_STORE_PUBKEY_Marshal(const TPM_STORE_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_KEY12_PUBKEY_Marshal(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PUBKEY_Marshal(const TPM_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_KEY12_Marshal(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_QUOTE_INFO2_Marshal(const TPM_QUOTE_INFO2 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_EK_BLOB_Marshal(const TPM_EK_BLOB *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_EK_BLOB_ACTIVATE_Marshal(const TPM_EK_BLOB_ACTIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_ATTRIBUTES_Marshal(const TPM_NV_ATTRIBUTES *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_DATA_PUBLIC_Marshal(const TPM_NV_DATA_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_CAP_VERSION_INFO_Marshal(const TPM_CAP_VERSION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif
