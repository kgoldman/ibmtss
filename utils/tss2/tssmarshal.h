/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal.h 730 2016-08-23 21:09:53Z kgoldman $		*/
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

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that have to marshal / unmarshal
   structures for file save / load.
*/

#ifndef TSSMARSHAL_H
#define TSSMARSHAL_H

#ifndef TPM_TSS
#define TPM_TSS
#endif

#include "BaseTypes.h"
#include <tss2/TPM_Types.h>

#include "ActivateCredential_fp.h"
#include "CertifyCreation_fp.h"
#include "Certify_fp.h"
#include "ChangeEPS_fp.h"
#include "ChangePPS_fp.h"
#include "ClearControl_fp.h"
#include "Clear_fp.h"
#include "ClockRateAdjust_fp.h"
#include "ClockSet_fp.h"
#include "Commit_fp.h"
#include "Commit_fp.h"
#include "ContextLoad_fp.h"
#include "ContextSave_fp.h"
#include "CreatePrimary_fp.h"
#include "Create_fp.h"
#include "DictionaryAttackLockReset_fp.h"
#include "DictionaryAttackParameters_fp.h"
#include "Duplicate_fp.h"
#include "ECC_Parameters_fp.h"
#include "ECDH_KeyGen_fp.h"
#include "ECDH_ZGen_fp.h"
#include "EC_Ephemeral_fp.h"
#include "EncryptDecrypt_fp.h"
#include "EventSequenceComplete_fp.h"
#include "EvictControl_fp.h"
#include "FlushContext_fp.h"
#include "GetCapability_fp.h"
#include "GetCommandAuditDigest_fp.h"
#include "GetRandom_fp.h"
#include "GetSessionAuditDigest_fp.h"
#include "GetTestResult_fp.h"
#include "GetTime_fp.h"
#include "HMAC_Start_fp.h"
#include "HMAC_fp.h"
#include "HashSequenceStart_fp.h"
#include "Hash_fp.h"
#include "HierarchyChangeAuth_fp.h"
#include "HierarchyControl_fp.h"
#include "Import_fp.h"
#include "IncrementalSelfTest_fp.h"
#include "LoadExternal_fp.h"
#include "Load_fp.h"
#include "MakeCredential_fp.h"
#include "NV_Certify_fp.h"
#include "NV_ChangeAuth_fp.h"
#include "NV_DefineSpace_fp.h"
#include "NV_Extend_fp.h"
#include "NV_GlobalWriteLock_fp.h"
#include "NV_Increment_fp.h"
#include "NV_ReadLock_fp.h"
#include "NV_ReadPublic_fp.h"
#include "NV_Read_fp.h"
#include "NV_SetBits_fp.h"
#include "NV_UndefineSpaceSpecial_fp.h"
#include "NV_UndefineSpace_fp.h"
#include "NV_WriteLock_fp.h"
#include "NV_Write_fp.h"
#include "ObjectChangeAuth_fp.h"
#include "PCR_Allocate_fp.h"
#include "PCR_Event_fp.h"
#include "PCR_Extend_fp.h"
#include "PCR_Read_fp.h"
#include "PCR_Reset_fp.h"
#include "PCR_SetAuthPolicy_fp.h"
#include "PCR_SetAuthValue_fp.h"
#include "PP_Commands_fp.h"
#include "PolicyAuthValue_fp.h"
#include "PolicyAuthorize_fp.h"
#include "PolicyCommandCode_fp.h"
#include "PolicyCounterTimer_fp.h"
#include "PolicyCpHash_fp.h"
#include "PolicyDuplicationSelect_fp.h"
#include "PolicyGetDigest_fp.h"
#include "PolicyLocality_fp.h"
#include "PolicyNV_fp.h"
#include "PolicyNvWritten_fp.h"
#include "PolicyNameHash_fp.h"
#include "PolicyOR_fp.h"
#include "PolicyPCR_fp.h"
#include "PolicyPassword_fp.h"
#include "PolicyPhysicalPresence_fp.h"
#include "PolicyRestart_fp.h"
#include "PolicySecret_fp.h"
#include "PolicySigned_fp.h"
#include "PolicyTicket_fp.h"
#include "Quote_fp.h"
#include "RSA_Decrypt_fp.h"
#include "RSA_Encrypt_fp.h"
#include "ReadClock_fp.h"
#include "ReadPublic_fp.h"
#include "Rewrap_fp.h"
#include "SelfTest_fp.h"
#include "SequenceComplete_fp.h"
#include "SequenceUpdate_fp.h"
#include "SetAlgorithmSet_fp.h"
#include "SetCommandCodeAuditStatus_fp.h"
#include "SetPrimaryPolicy_fp.h"
#include "Shutdown_fp.h"
#include "Sign_fp.h"
#include "StartAuthSession_fp.h"
#include "Startup_fp.h"
#include "StirRandom_fp.h"
#include "TestParms_fp.h"
#include "Unseal_fp.h"
#include "VerifySignature_fp.h"
#include "ZGen_2Phase_fp.h"

TPM_RC
TSS_Startup_In_Marshal(Startup_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Shutdown_In_Marshal(Shutdown_In  *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SelfTest_In_Marshal(SelfTest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_IncrementalSelfTest_In_Marshal(IncrementalSelfTest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_StartAuthSession_In_Marshal(StartAuthSession_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyRestart_In_Marshal(PolicyRestart_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Create_In_Marshal(Create_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Load_In_Marshal(Load_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_LoadExternal_In_Marshal(LoadExternal_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ReadPublic_In_Marshal(ReadPublic_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ActivateCredential_In_Marshal(ActivateCredential_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_MakeCredential_In_Marshal(MakeCredential_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Unseal_In_Marshal(Unseal_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ObjectChangeAuth_In_Marshal(ObjectChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Duplicate_In_Marshal(Duplicate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Rewrap_In_Marshal(Rewrap_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Import_In_Marshal(Import_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_RSA_Encrypt_In_Marshal(RSA_Encrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_RSA_Decrypt_In_Marshal(RSA_Decrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECDH_KeyGen_In_Marshal(ECDH_KeyGen_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECDH_ZGen_In_Marshal(ECDH_ZGen_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECC_Parameters_In_Marshal(ECC_Parameters_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ZGen_2Phase_In_Marshal(ZGen_2Phase_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EncryptDecrypt_In_Marshal(EncryptDecrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Hash_In_Marshal(Hash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HMAC_In_Marshal(HMAC_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetRandom_In_Marshal(GetRandom_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_StirRandom_In_Marshal(StirRandom_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HMAC_Start_In_Marshal(HMAC_Start_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HashSequenceStart_In_Marshal(HashSequenceStart_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SequenceUpdate_In_Marshal(SequenceUpdate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SequenceComplete_In_Marshal(SequenceComplete_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EventSequenceComplete_In_Marshal(EventSequenceComplete_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Certify_In_Marshal(Certify_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_CertifyCreation_In_Marshal(CertifyCreation_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Quote_In_Marshal(Quote_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetSessionAuditDigest_In_Marshal(GetSessionAuditDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetCommandAuditDigest_In_Marshal(GetCommandAuditDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetTime_In_Marshal(GetTime_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Commit_In_Marshal(Commit_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EC_Ephemeral_In_Marshal(EC_Ephemeral_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_VerifySignature_In_Marshal(VerifySignature_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Sign_In_Marshal(Sign_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SetCommandCodeAuditStatus_In_Marshal(SetCommandCodeAuditStatus_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Extend_In_Marshal(PCR_Extend_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Event_In_Marshal(PCR_Event_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Read_In_Marshal(PCR_Read_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Allocate_In_Marshal(PCR_Allocate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_SetAuthPolicy_In_Marshal(PCR_SetAuthPolicy_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_SetAuthValue_In_Marshal(PCR_SetAuthValue_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Reset_In_Marshal(PCR_Reset_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicySigned_In_Marshal(PolicySigned_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicySecret_In_Marshal(PolicySecret_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyTicket_In_Marshal(PolicyTicket_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyOR_In_Marshal(PolicyOR_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyPCR_In_Marshal(PolicyPCR_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyLocality_In_Marshal(PolicyLocality_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyNV_In_Marshal(PolicyNV_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyCounterTimer_In_Marshal(PolicyCounterTimer_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyCommandCode_In_Marshal(PolicyCommandCode_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyPhysicalPresence_In_Marshal(PolicyPhysicalPresence_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyCpHash_In_Marshal(PolicyCpHash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyNameHash_In_Marshal(PolicyNameHash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyDuplicationSelect_In_Marshal(PolicyDuplicationSelect_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyAuthorize_In_Marshal(PolicyAuthorize_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyAuthValue_In_Marshal(PolicyAuthValue_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyPassword_In_Marshal(PolicyPassword_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyGetDigest_In_Marshal(PolicyGetDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyNvWritten_In_Marshal(PolicyNvWritten_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_CreatePrimary_In_Marshal(CreatePrimary_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HierarchyControl_In_Marshal(HierarchyControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SetPrimaryPolicy_In_Marshal(SetPrimaryPolicy_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ChangePPS_In_Marshal(ChangePPS_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ChangeEPS_In_Marshal(ChangeEPS_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Clear_In_Marshal(Clear_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ClearControl_In_Marshal(ClearControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HierarchyChangeAuth_In_Marshal(HierarchyChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_DictionaryAttackLockReset_In_Marshal(DictionaryAttackLockReset_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_DictionaryAttackParameters_In_Marshal(DictionaryAttackParameters_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PP_Commands_In_Marshal(PP_Commands_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SetAlgorithmSet_In_Marshal(SetAlgorithmSet_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ContextSave_In_Marshal(ContextSave_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ContextLoad_In_Marshal(ContextLoad_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_FlushContext_In_Marshal(FlushContext_In *source, UINT16 *written, BYTE **buffer, INT32 *size) ;
TPM_RC
TSS_EvictControl_In_Marshal(EvictControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ClockSet_In_Marshal(ClockSet_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ClockRateAdjust_In_Marshal(ClockRateAdjust_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetCapability_In_Marshal(GetCapability_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_TestParms_In_Marshal(TestParms_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_DefineSpace_In_Marshal(NV_DefineSpace_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_UndefineSpace_In_Marshal(NV_UndefineSpace_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_UndefineSpaceSpecial_In_Marshal(NV_UndefineSpaceSpecial_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_ReadPublic_In_Marshal(NV_ReadPublic_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Write_In_Marshal(NV_Write_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Increment_In_Marshal(NV_Increment_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Extend_In_Marshal(NV_Extend_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_SetBits_In_Marshal(NV_SetBits_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_WriteLock_In_Marshal(NV_WriteLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_GlobalWriteLock_In_Marshal(NV_GlobalWriteLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Read_In_Marshal(NV_Read_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_ReadLock_In_Marshal(NV_ReadLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_ChangeAuth_In_Marshal(NV_ChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Certify_In_Marshal(NV_Certify_In *source, UINT16 *written, BYTE **buffer, INT32 *size);

TPM_RC
TSS_IncrementalSelfTest_Out_Unmarshal(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetTestResult_Out_Unmarshal(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_StartAuthSession_Out_Unmarshal(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Create_Out_Unmarshal(Create_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Load_Out_Unmarshal(Load_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_LoadExternal_Out_Unmarshal(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ReadPublic_Out_Unmarshal(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ActivateCredential_Out_Unmarshal(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_MakeCredential_Out_Unmarshal(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Unseal_Out_Unmarshal(Unseal_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ObjectChangeAuth_Out_Unmarshal(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Duplicate_Out_Unmarshal(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Rewrap_Out_Unmarshal(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Import_Out_Unmarshal(Import_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_RSA_Encrypt_Out_Unmarshal(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_RSA_Decrypt_Out_Unmarshal(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECDH_KeyGen_Out_Unmarshal(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECDH_ZGen_Out_Unmarshal(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ECC_Parameters_Out_Unmarshal(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ZGen_2Phase_Out_Unmarshal(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EncryptDecrypt_Out_Unmarshal(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Hash_Out_Unmarshal(Hash_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HMAC_Out_Unmarshal(HMAC_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetRandom_Out_Unmarshal(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HMAC_Start_Out_Unmarshal(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_HashSequenceStart_Out_Unmarshal(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_SequenceComplete_Out_Unmarshal(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EventSequenceComplete_Out_Unmarshal(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Certify_Out_Unmarshal(Certify_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_CertifyCreation_Out_Unmarshal(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Quote_Out_Unmarshal(Quote_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetSessionAuditDigest_Out_Unmarshal(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetCommandAuditDigest_Out_Unmarshal(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetTime_Out_Unmarshal(GetTime_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Commit_Out_Unmarshal(Commit_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_EC_Ephemeral_Out_Unmarshal(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_VerifySignature_Out_Unmarshal(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_Sign_Out_Unmarshal(Sign_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Event_Out_Unmarshal(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Read_Out_Unmarshal(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PCR_Allocate_Out_Unmarshal(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicySigned_Out_Unmarshal(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicySecret_Out_Unmarshal(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_PolicyGetDigest_Out_Unmarshal(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_CreatePrimary_Out_Unmarshal(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ContextSave_Out_Unmarshal(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ContextLoad_Out_Unmarshal(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_ReadClock_Out_Unmarshal(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_GetCapability_Out_Unmarshal(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_ReadPublic_Out_Unmarshal(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Read_Out_Unmarshal(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NV_Certify_Out_Unmarshal(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);

LIB_EXPORT TPM_RC
TSS_UINT8_Marshal(UINT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_INT8_Marshal(INT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT16_Marshal(UINT16 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT32_Marshal(UINT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_INT32_Marshal(INT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT64_Marshal(UINT64 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_Array_Marshal(BYTE *source, UINT16 sourceSize, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_Marshal(TPM2B *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_KEY_BITS_Marshal(TPM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_GENERATED_Marshal(TPM_GENERATED *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ALG_ID_Marshal(TPM_ALG_ID *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ECC_CURVE_Marshal(TPM_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_RC_Marshal(TPM_RC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CLOCK_ADJUST_Marshal(TPM_CLOCK_ADJUST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_EO_Marshal(TPM_EO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ST_Marshal(TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_SU_Marshal(TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_SE_Marshal(TPM_SE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CAP_Marshal(TPM_CAP *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_PT_Marshal(TPM_PT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_PT_PCR_Marshal(TPM_PT_PCR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_HANDLE_Marshal(TPM_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_ALGORITHM_Marshal(TPMA_ALGORITHM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_OBJECT_Marshal(TPMA_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_SESSION_Marshal(TPMA_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_LOCALITY_Marshal(TPMA_LOCALITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CC_Marshal(TPM_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_CC_Marshal(TPMA_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_YES_NO_Marshal(TPMI_YES_NO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_OBJECT_Marshal(TPMI_DH_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_PERSISTENT_Marshal(TPMI_DH_PERSISTENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_ENTITY_Marshal(TPMI_DH_ENTITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_PCR_Marshal(TPMI_DH_PCR  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Marshal(TPMI_SH_AUTH_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_HMAC_Marshal(TPMI_SH_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_POLICY_Marshal(TPMI_SH_POLICY*source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_CONTEXT_Marshal(TPMI_DH_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_HIERARCHY_Marshal(TPMI_RH_HIERARCHY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_ENABLES_Marshal(TPMI_RH_ENABLES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(TPMI_RH_HIERARCHY_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_PLATFORM_Marshal(TPMI_RH_PLATFORM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Marshal(TPMI_RH_ENDORSEMENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_PROVISION_Marshal(TPMI_RH_PROVISION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_CLEAR_Marshal(TPMI_RH_CLEAR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_NV_AUTH_Marshal(TPMI_RH_NV_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_LOCKOUT_Marshal(TPMI_RH_LOCKOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_NV_INDEX_Marshal(TPMI_RH_NV_INDEX *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_HASH_Marshal(TPMI_ALG_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_Marshal(TPMI_ALG_SYM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Marshal(TPMI_ALG_SYM_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_MODE_Marshal(TPMI_ALG_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_KDF_Marshal(TPMI_ALG_KDF *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Marshal(TPMI_ALG_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(TPMI_ECC_KEY_EXCHANGE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Marshal(TPMI_ST_COMMAND_TAG *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_HA_Marshal(TPMU_HA *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_HA_Marshal(TPMT_HA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_DIGEST_Marshal(TPM2B_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_DATA_Marshal(TPM2B_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NONCE_Marshal(TPM2B_NONCE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_AUTH_Marshal(TPM2B_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_OPERAND_Marshal(TPM2B_OPERAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_EVENT_Marshal(TPM2B_EVENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_IV_Marshal(TPM2B_IV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NAME_Marshal(TPM2B_NAME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Marshal(TPMS_TAGGED_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Marshal(TPMS_TAGGED_PCR_SELECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_CC_Marshal(TPML_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_CCA_Marshal(TPML_CCA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ALG_Marshal(TPML_ALG *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_HANDLE_Marshal(TPML_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_DIGEST_Marshal(TPML_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(TPML_TAGGED_TPM_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(TPML_TAGGED_PCR_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_CAPABILITY_DATA_Marshal(TPMS_CAPABILITY_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Marshal(TPMS_TIME_ATTEST_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(TPMS_COMMAND_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Marshal(TPMS_SESSION_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Marshal(TPMS_NV_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ST_ATTEST_Marshal(TPMI_ST_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_ATTEST_Marshal(TPMU_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_ATTEST_Marshal(TPMS_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ATTEST_Marshal(TPM2B_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_AUTH_COMMAND_Marshal(TPMS_AUTH_COMMAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_AES_KEY_BITS_Marshal(TPMI_AES_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Marshal(TPMS_SYMCIPHER_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Marshal(TPM2B_SENSITIVE_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Marshal(TPMS_SENSITIVE_CREATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Marshal(TPM2B_SENSITIVE_CREATE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_HASH_Marshal(TPMS_SCHEME_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(TPMI_ALG_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_HMAC_Marshal(TPMS_SCHEME_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(TPMS_SIG_SCHEME_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(TPMS_SIG_SCHEME_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(TPMS_SIG_SCHEME_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Marshal(TPMS_SIG_SCHEME_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(TPMS_SIG_SCHEME_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(TPMS_SIG_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SIG_SCHEME_Marshal(TPMU_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SIG_SCHEME_Marshal(TPMT_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Marshal(TPMS_ENC_SCHEME_OAEP *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Marshal(TPMS_ENC_SCHEME_RSAES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Marshal(TPMS_KEY_SCHEME_ECDH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(TPMS_KEY_SCHEME_ECMQV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_MGF1_Marshal(TPMS_SCHEME_MGF1 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(TPMS_SCHEME_KDF1_SP800_56A *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF2_Marshal(TPMS_SCHEME_KDF2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(TPMS_SCHEME_KDF1_SP800_108 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Marshal(TPMI_ALG_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Marshal(TPMI_ALG_RSA_DECRYPT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_RSA_DECRYPT_Marshal(TPMT_RSA_DECRYPT  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(TPM2B_PUBLIC_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RSA_KEY_BITS_Marshal(TPMI_RSA_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(TPM2B_PRIVATE_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Marshal(TPMI_ALG_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ECC_CURVE_Marshal(TPMI_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshal(TPMS_ALGORITHM_DETAIL_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSA_Marshal(TPMS_SIGNATURE_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Marshal(TPMS_SIGNATURE_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Marshal(TPMS_SIGNATURE_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECC_Marshal(TPMS_SIGNATURE_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Marshal(TPMS_SIGNATURE_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Marshal(TPMS_SIGNATURE_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_SM2_Marshal(TPMS_SIGNATURE_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Marshal(TPMS_SIGNATURE_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Marshal(TPM2B_ENCRYPTED_SECRET *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_PUBLIC_Marshal(TPMI_ALG_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Marshal(TPMS_KEYEDHASH_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_PUBLIC_Marshal(TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_Marshal(TPM2B_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_NV_Marshal(TPMA_NV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Marshal(TPM2B_CONTEXT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CONTEXT_Marshal(TPMS_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);

#endif
