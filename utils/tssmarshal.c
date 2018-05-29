/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal.c 1157 2018-04-17 14:09:56Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2018.					*/
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

#include <tss2/tssmarshal.h>
#include <tss2/tsserror.h>
#include <tss2/tssprint.h>
#include <tss2/Unmarshal_fp.h>

/* This file holds:

   Primary shared marshal functions
   
   TPM 2.0 command marshal functions
   TPM 2.0 response unmarshal functions
   
   TPM 2.0 Structure marshal functions

   - for historical reasons, previously shared code with the TPM 2.0 SW TPM
   
   TPM 2.0 structure unmarshal functions are in Unmarshal.c
   TPM 2.0 command unmarshal functions (for error checking) are in Commands.c
*/

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

/* Marshal functions shared by TPM 1.2 and TPM 2.0 */

TPM_RC
TSS_UINT8_Marshal(const UINT8 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {	/* if buffer is NULL, don't marshal, just return written */
	/* if size is NULL, ignore it, else check sufficient */
	if ((size == NULL) || (*size >= sizeof(UINT8))) {
	    /* marshal, move the buffer */
	    (*buffer)[0] = *source;
	    *buffer += sizeof(UINT8);
	    /* is size was supplied, update it */
	    if (size != NULL) {
		*size -= sizeof(UINT8);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(UINT8);
    return rc;
}
    
TPM_RC
TSS_INT8_Marshal(const INT8 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    rc = TSS_UINT8_Marshal((const UINT8 *)source, written, buffer, size);
    return rc;
}

TPM_RC
TSS_UINT16_Marshal(const UINT16 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(uint16_t))) {

	    (*buffer)[0] = (BYTE)((*source >> 8) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 0) & 0xff);
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

TPM_RC
TSS_UINT32_Marshal(const UINT32 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(uint32_t))) {

	    (*buffer)[0] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >>  0) & 0xff);
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

TPM_RC
TSS_INT32_Marshal(const INT32 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    rc = TSS_UINT32_Marshal((const UINT32 *)source, written, buffer, size);
    return rc;
}

TPM_RC
TSS_UINT64_Marshal(const UINT64 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(UINT64))) {

	    (*buffer)[0] = (BYTE)((*source >> 56) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 48) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >> 40) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >> 32) & 0xff);
	    (*buffer)[4] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[5] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[6] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[7] = (BYTE)((*source >>  0) & 0xff);
	    *buffer += sizeof(UINT64);

	    if (size != NULL) {
		*size -= sizeof(UINT64);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(UINT64);
    return rc;
}

TPM_RC
TSS_Array_Marshal(const BYTE *source, uint16_t sourceSize, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sourceSize)) {
	    memcpy(*buffer, source, sourceSize);

	    *buffer += sourceSize;

	    if (size != NULL) {
		*size -= sourceSize;
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sourceSize;
    return rc;
}

#ifdef TPM_TPM20

/*
  TPM 2.0 Command parameter marshaling
*/

TPM_RC
TSS_Startup_In_Marshal(const Startup_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_SU_Marshal(&source->startupType, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Shutdown_In_Marshal(const Shutdown_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_SU_Marshal(&source->shutdownType, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SelfTest_In_Marshal(const SelfTest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->fullTest, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_IncrementalSelfTest_In_Marshal(const IncrementalSelfTest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_ALG_Marshal(&source->toTest, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StartAuthSession_In_Marshal(const StartAuthSession_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->tpmKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshal(&source->bind, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonceCaller, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshal(&source->encryptedSalt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_SE_Marshal(&source->sessionType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_Marshal(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->authHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyRestart_In_Marshal(const PolicyRestart_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->sessionHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Create_In_Marshal(const Create_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshal(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshal(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->outsideInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->creationPCR, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Load_In_Marshal(const Load_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshal(&source->inPrivate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshal(&source->inPublic, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_LoadExternal_In_Marshal(const LoadExternal_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	/* optional parameter, use size as flag */
	if (source->inPrivate.b.size == 0) {		/* not present */
	    uint16_t zero = 0;
	    rc = TSS_UINT16_Marshal(&zero, written, buffer, size);
	}
	else {
	    rc = TSS_TPM2B_SENSITIVE_Marshal(&source->inPrivate, written, buffer, size);
	}
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshal(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ReadPublic_In_Marshal(const ReadPublic_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ActivateCredential_In_Marshal(const ActivateCredential_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->activateHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ID_OBJECT_Marshal(&source->credentialBlob, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshal(&source->secret, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_MakeCredential_In_Marshal(const MakeCredential_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->credential, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->objectName, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Unseal_In_Marshal(const Unseal_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->itemHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ObjectChangeAuth_In_Marshal(const ObjectChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreateLoaded_In_Marshal(const CreateLoaded_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshal(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_TEMPLATE_Marshal(&source->inPublic, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Duplicate_In_Marshal(const Duplicate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->newParentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->encryptionKeyIn, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetricAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Rewrap_In_Marshal(const Rewrap_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->oldParent, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->newParent, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshal(&source->inDuplicate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->name, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshal(&source->inSymSeed, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Import_In_Marshal(const Import_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->encryptionKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshal(&source->objectPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshal(&source->duplicate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshal(&source->inSymSeed, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetricAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Encrypt_In_Marshal(const RSA_Encrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&source->message, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_DECRYPT_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->label, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Decrypt_In_Marshal(const RSA_Decrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&source->cipherText, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_DECRYPT_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->label, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_KeyGen_In_Marshal(const ECDH_KeyGen_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_ZGen_In_Marshal(const ECDH_ZGen_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshal(&source->inPoint, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECC_Parameters_In_Marshal(const ECC_Parameters_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshal(&source->curveID, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ZGen_2Phase_In_Marshal(const ZGen_2Phase_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshal(&source->inQsB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshal(&source->inQeB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->counter, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt_In_Marshal(const EncryptDecrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->decrypt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_CIPHER_MODE_Marshal(&source->mode, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_IV_Marshal(&source->ivIn, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->inData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt2_In_Marshal(const EncryptDecrypt2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->inData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->decrypt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_CIPHER_MODE_Marshal(&source->mode, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_IV_Marshal(&source->ivIn, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Hash_In_Marshal(const Hash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->data, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_In_Marshal(const HMAC_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->buffer, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetRandom_In_Marshal(const GetRandom_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->bytesRequested, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StirRandom_In_Marshal(const StirRandom_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshal(&source->inData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Start_In_Marshal(const HMAC_Start_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HashSequenceStart_In_Marshal(const HashSequenceStart_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SequenceUpdate_In_Marshal(const SequenceUpdate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->buffer, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SequenceComplete_In_Marshal(const SequenceComplete_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->buffer, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EventSequenceComplete_In_Marshal(const EventSequenceComplete_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshal(&source->buffer, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Certify_In_Marshal(const Certify_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CertifyCreation_In_Marshal(const CertifyCreation_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->creationHash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_CREATION_Marshal(&source->creationTicket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Quote_In_Marshal(const Quote_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->PCRselect, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetSessionAuditDigest_In_Marshal(const GetSessionAuditDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshal(&source->privacyAdminHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_HMAC_Marshal(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCommandAuditDigest_In_Marshal(const GetCommandAuditDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshal(&source->privacyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetTime_In_Marshal(const GetTime_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshal(&source->privacyAdminHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Commit_In_Marshal(const Commit_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshal(&source->P1, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshal(&source->s2, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->y2, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EC_Ephemeral_In_Marshal(const EC_Ephemeral_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshal(&source->curveID, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_VerifySignature_In_Marshal(const VerifySignature_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIGNATURE_Marshal(&source->signature, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Sign_In_Marshal(const Sign_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_HASHCHECK_Marshal(&source->validation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetCommandCodeAuditStatus_In_Marshal(const SetCommandCodeAuditStatus_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->auditAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshal(&source->setList, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshal(&source->clearList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Extend_In_Marshal(const PCR_Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Marshal(&source->digests, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Event_In_Marshal(const PCR_Event_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_EVENT_Marshal(&source->eventData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Read_In_Marshal(const PCR_Read_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->pcrSelectionIn, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Allocate_In_Marshal(const PCR_Allocate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->pcrAllocation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_SetAuthPolicy_In_Marshal(const PCR_SetAuthPolicy_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrNum, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_SetAuthValue_In_Marshal(const PCR_SetAuthValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->auth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Reset_In_Marshal(const PCR_Reset_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshal(&source->pcrHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySigned_In_Marshal(const PolicySigned_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->authObject, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_INT32_Marshal(&source->expiration, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIGNATURE_Marshal(&source->auth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySecret_In_Marshal(const PolicySecret_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_INT32_Marshal(&source->expiration, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyTicket_In_Marshal(const PolicyTicket_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_TIMEOUT_Marshal(&source->timeout, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->authName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_AUTH_Marshal(&source->ticket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyOR_In_Marshal(const PolicyOR_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_Marshal(&source->pHashList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPCR_In_Marshal(const PolicyPCR_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->pcrDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->pcrs, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyLocality_In_Marshal(const PolicyLocality_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_LOCALITY_Marshal(&source->locality, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNV_In_Marshal(const PolicyNV_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_OPERAND_Marshal(&source->operandB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_EO_Marshal(&source->operation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCounterTimer_In_Marshal(const PolicyCounterTimer_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_OPERAND_Marshal(&source->operandB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_EO_Marshal(&source->operation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCommandCode_In_Marshal(const PolicyCommandCode_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_CC_Marshal(&source->code, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPhysicalPresence_In_Marshal(const PolicyPhysicalPresence_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCpHash_In_Marshal(const PolicyCpHash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->cpHashA, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNameHash_In_Marshal(const PolicyNameHash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->nameHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyDuplicationSelect_In_Marshal(const PolicyDuplicationSelect_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->objectName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->newParentName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->includeObject, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthorize_In_Marshal(const PolicyAuthorize_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->approvedPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->keySign, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_VERIFIED_Marshal(&source->checkTicket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthValue_In_Marshal(const PolicyAuthValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPassword_In_Marshal(const PolicyPassword_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyGetDigest_In_Marshal(const PolicyGetDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNvWritten_In_Marshal(const PolicyNvWritten_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->writtenSet, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyTemplate_In_Marshal(const PolicyTemplate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->templateHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthorizeNV_In_Marshal(const PolicyAuthorizeNV_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshal(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreatePrimary_In_Marshal(const CreatePrimary_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->primaryHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshal(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshal(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->outsideInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->creationPCR, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HierarchyControl_In_Marshal(const HierarchyControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENABLES_Marshal(&source->enable, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->state, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetPrimaryPolicy_In_Marshal(const SetPrimaryPolicy_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ChangePPS_In_Marshal(const ChangePPS_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ChangeEPS_In_Marshal(const ChangeEPS_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Clear_In_Marshal(const Clear_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_CLEAR_Marshal(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClearControl_In_Marshal(const ClearControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_CLEAR_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->disable, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HierarchyChangeAuth_In_Marshal(const HierarchyChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_DictionaryAttackLockReset_In_Marshal(const DictionaryAttackLockReset_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_LOCKOUT_Marshal(&source->lockHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_DictionaryAttackParameters_In_Marshal(const DictionaryAttackParameters_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_LOCKOUT_Marshal(&source->lockHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->newMaxTries, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->newRecoveryTime, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->lockoutRecovery, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PP_Commands_In_Marshal(const PP_Commands_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshal(&source->setList, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshal(&source->clearList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetAlgorithmSet_In_Marshal(const SetAlgorithmSet_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->algorithmSet, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextSave_In_Marshal(const ContextSave_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_CONTEXT_Marshal(&source->saveHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextLoad_In_Marshal(const ContextLoad_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_CONTEXT_Marshal(&source->context, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_FlushContext_In_Marshal(const FlushContext_In *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_CONTEXT_Marshal(&source->flushHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EvictControl_In_Marshal(const EvictControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_PERSISTENT_Marshal(&source->persistentHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClockSet_In_Marshal(const ClockSet_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->newTime, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClockRateAdjust_In_Marshal(const ClockRateAdjust_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_CLOCK_ADJUST_Marshal(&source->rateAdjust, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCapability_In_Marshal(const GetCapability_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_CAP_Marshal(&source->capability, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->property, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->propertyCount, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TestParms_In_Marshal(const TestParms_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_PARMS_Marshal(&source->parameters, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_DefineSpace_In_Marshal(const NV_DefineSpace_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NV_PUBLIC_Marshal(&source->publicInfo, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_UndefineSpace_In_Marshal(const NV_UndefineSpace_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_UndefineSpaceSpecial_In_Marshal(const NV_UndefineSpaceSpecial_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshal(&source->platform, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadPublic_In_Marshal(const NV_ReadPublic_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Write_In_Marshal(const NV_Write_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshal(&source->data, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Increment_In_Marshal(const NV_Increment_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Extend_In_Marshal(const NV_Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshal(&source->data, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_SetBits_In_Marshal(const NV_SetBits_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->bits, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_WriteLock_In_Marshal(const NV_WriteLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_GlobalWriteLock_In_Marshal(const NV_GlobalWriteLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshal(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Read_In_Marshal(const NV_Read_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadLock_In_Marshal(const NV_ReadLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ChangeAuth_In_Marshal(const NV_ChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Certify_In_Marshal(const NV_Certify_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshal(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshal(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshal(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    return rc;
}

/*
  TPM 2.0 Response parameter unmarshaling
*/

TPM_RC
TSS_IncrementalSelfTest_Out_Unmarshal(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPML_ALG_Unmarshal(&target->toDoList, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetTestResult_Out_Unmarshal(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t parameterSize;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_MAX_BUFFER_Unmarshal(&target->outData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM_RC_Unmarshal(&target->testResult, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StartAuthSession_Out_Unmarshal(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_SH_AUTH_SESSION_Unmarshal(&target->sessionHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NONCE_Unmarshal(&target->nonceTPM, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Create_Out_Unmarshal(Create_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->outPrivate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_Unmarshal(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_CREATION_DATA_Unmarshal(&target->creationData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->creationHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_CREATION_Unmarshal(&target->creationTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Load_Out_Unmarshal(Load_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPM_HANDLE_Unmarshal(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_LoadExternal_Out_Unmarshal(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPM_HANDLE_Unmarshal(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ReadPublic_Out_Unmarshal(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_Unmarshal(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->name, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->qualifiedName, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ActivateCredential_Out_Unmarshal(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->certInfo, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_MakeCredential_Out_Unmarshal(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ID_OBJECT_Unmarshal(&target->credentialBlob, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&target->secret, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Unseal_Out_Unmarshal(Unseal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_SENSITIVE_DATA_Unmarshal(&target->outData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ObjectChangeAuth_Out_Unmarshal(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->outPrivate, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreateLoaded_Out_Unmarshal(CreateLoaded_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPM_HANDLE_Unmarshal(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->outPrivate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_Unmarshal(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Duplicate_Out_Unmarshal(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DATA_Unmarshal(&target->encryptionKeyOut, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->duplicate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&target->outSymSeed, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Rewrap_Out_Unmarshal(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->outDuplicate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&target->outSymSeed, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Import_Out_Unmarshal(Import_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PRIVATE_Unmarshal(&target->outPrivate, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Encrypt_Out_Unmarshal(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal(&target->outData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Decrypt_Out_Unmarshal(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal(&target->message, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_KeyGen_Out_Unmarshal(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->zPoint, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->pubPoint, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_ZGen_Out_Unmarshal(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->outPoint, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECC_Parameters_Out_Unmarshal(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(&target->parameters, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ZGen_2Phase_Out_Unmarshal(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->outZ1, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->outZ2, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt_Out_Unmarshal(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_MAX_BUFFER_Unmarshal(&target->outData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_IV_Unmarshal(&target->ivOut, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt2_Out_Unmarshal(EncryptDecrypt2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    return TSS_EncryptDecrypt_Out_Unmarshal((EncryptDecrypt_Out *)target, tag, buffer, size);
}
TPM_RC
TSS_Hash_Out_Unmarshal(Hash_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->outHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_HASHCHECK_Unmarshal(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Out_Unmarshal(HMAC_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->outHMAC, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetRandom_Out_Unmarshal(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->randomBytes, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Start_Out_Unmarshal(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_DH_OBJECT_Unmarshal(&target->sequenceHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_HashSequenceStart_Out_Unmarshal(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_DH_OBJECT_Unmarshal(&target->sequenceHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_SequenceComplete_Out_Unmarshal(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->result, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_HASHCHECK_Unmarshal(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EventSequenceComplete_Out_Unmarshal(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPML_DIGEST_VALUES_Unmarshal(&target->results, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Certify_Out_Unmarshal(Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_CertifyCreation_Out_Unmarshal(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_Quote_Out_Unmarshal(Quote_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->quoted, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_GetSessionAuditDigest_Out_Unmarshal(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->auditInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_GetCommandAuditDigest_Out_Unmarshal(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->auditInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_GetTime_Out_Unmarshal(GetTime_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->timeInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_Commit_Out_Unmarshal(Commit_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->K, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->L, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->E, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshal(&target->counter, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EC_Ephemeral_Out_Unmarshal(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ECC_POINT_Unmarshal(&target->Q, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshal(&target->counter, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_VerifySignature_Out_Unmarshal(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_VERIFIED_Unmarshal(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Sign_Out_Unmarshal(Sign_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_PCR_Event_Out_Unmarshal(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPML_DIGEST_VALUES_Unmarshal(&target->digests, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Read_Out_Unmarshal(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshal(&target->pcrUpdateCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPML_PCR_SELECTION_Unmarshal(&target->pcrSelectionOut, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPML_DIGEST_Unmarshal(&target->pcrValues, buffer, size, 0);
    }
    return rc;
}
TPM_RC
TSS_PCR_Allocate_Out_Unmarshal(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_YES_NO_Unmarshal(&target->allocationSuccess, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshal(&target->maxPCR, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshal(&target->sizeNeeded, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshal(&target->sizeAvailable, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySigned_Out_Unmarshal(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_TIMEOUT_Unmarshal(&target->timeout, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_AUTH_Unmarshal(&target->policyTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySecret_Out_Unmarshal(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_TIMEOUT_Unmarshal(&target->timeout, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_AUTH_Unmarshal(&target->policyTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyGetDigest_Out_Unmarshal(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->policyDigest, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreatePrimary_Out_Unmarshal(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPM_HANDLE_Unmarshal(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_PUBLIC_Unmarshal(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_CREATION_DATA_Unmarshal(&target->creationData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_DIGEST_Unmarshal(&target->creationHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_TK_CREATION_Unmarshal(&target->creationTicket, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextSave_Out_Unmarshal(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMS_CONTEXT_Unmarshal(&target->context, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextLoad_Out_Unmarshal(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_DH_CONTEXT_Unmarshal(&target->loadedHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_ReadClock_Out_Unmarshal(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMS_TIME_INFO_Unmarshal(&target->currentTime, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCapability_Out_Unmarshal(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMI_YES_NO_Unmarshal(&target->moreData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMS_CAPABILITY_DATA_Unmarshal(&target->capabilityData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadPublic_Out_Unmarshal(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NV_PUBLIC_Unmarshal(&target->nvPublic, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_NAME_Unmarshal(&target->nvName, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Read_Out_Unmarshal(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_MAX_NV_BUFFER_Unmarshal(&target->data, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Certify_Out_Unmarshal(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize           = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshal(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_ATTEST_Unmarshal(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TPMT_SIGNATURE_Unmarshal(&target->signature, buffer, size, NO);
    }
    return rc;
}

/*
  TPM 2.0 Structure marshaling
*/

TPM_RC
TSS_TPM2B_Marshal(const TPM2B *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&(source->size), written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(source->buffer, source->size, written, buffer, size);
    }
    return rc;
}

/* Table 5 - Definition of Types for Documentation Clarity */

TPM_RC
TSS_TPM_KEY_BITS_Marshal(const TPM_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}
   
/* Table 7 - Definition of (UINT32) TPM_GENERATED Constants <O> */

TPM_RC
TSS_TPM_GENERATED_Marshal(const TPM_GENERATED *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}
 
/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ALG_ID_Marshal(const TPM_ALG_ID *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 10 - Definition of (uint16_t) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

#ifdef TPM_ALG_ECC
TPM_RC
TSS_TPM_ECC_CURVE_Marshal(const TPM_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}
#endif

/* Table 17 - Definition of (UINT32) TPM_RC Constants (Actions) <OUT> */

TPM_RC
TSS_TPM_RC_Marshal(const TPM_RC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

TPM_RC
TSS_TPM_CLOCK_ADJUST_Marshal(const TPM_CLOCK_ADJUST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_INT8_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 19 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

TPM_RC
TSS_TPM_EO_Marshal(const TPM_EO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 20 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ST_Marshal(const TPM_ST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}
 
/* Table 21 - Definition of (UINT16) TPM_SU Constants <IN> */

TPM_RC
TSS_TPM_SU_Marshal(const TPM_ST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 22 - Definition of (UINT8) TPM_SE Constants <IN> */

TPM_RC
TSS_TPM_SE_Marshal(const TPM_SE  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 23 - Definition of (UINT32) TPM_CAP Constants  */

TPM_RC
TSS_TPM_CAP_Marshal(const TPM_CAP *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 24 - Definition of (UINT32) TPM_PT Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_Marshal(const TPM_PT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 25 - Definition of (UINT32) TPM_PT_PCR Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_PCR_Marshal(const TPM_PT_PCR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 27 - Definition of Types for Handles */

TPM_RC
TSS_TPM_HANDLE_Marshal(const TPM_HANDLE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 31 - Definition of (UINT32) TPMA_ALGORITHM Bits */

TPM_RC
TSS_TPMA_ALGORITHM_Marshal(const TPMA_ALGORITHM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 32 - Definition of (UINT32) TPMA_OBJECT Bits */

TPM_RC
TSS_TPMA_OBJECT_Marshal(const TPMA_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}
 
/* Table 33 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

TPM_RC
TSS_TPMA_SESSION_Marshal(const TPMA_SESSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 34 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

TPM_RC
TSS_TPMA_LOCALITY_Marshal(const TPMA_LOCALITY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

TPM_RC
TSS_TPM_CC_Marshal(const TPM_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

TPM_RC
TSS_TPMA_CC_Marshal(const TPMA_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 39 - Definition of (BYTE) TPMI_YES_NO Type */

TPM_RC
TSS_TPMI_YES_NO_Marshal(const TPMI_YES_NO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type */

TPM_RC
TSS_TPMI_DH_OBJECT_Marshal(const TPMI_DH_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type */

TPM_RC
TSS_TPMI_DH_PERSISTENT_Marshal(const TPMI_DH_PERSISTENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type <IN> */

TPM_RC
TSS_TPMI_DH_ENTITY_Marshal(const TPMI_DH_ENTITY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type <IN> */

TPM_RC
TSS_TPMI_DH_PCR_Marshal(const TPMI_DH_PCR  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Marshal(const TPMI_SH_AUTH_SESSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_HMAC_Marshal(const TPMI_SH_HMAC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_POLICY_Marshal(const TPMI_SH_POLICY*source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}
  
/* Table 47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type  */

TPM_RC
TSS_TPMI_DH_CONTEXT_Marshal(const TPMI_DH_CONTEXT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type  */

TPM_RC
TSS_TPMI_RH_HIERARCHY_Marshal(const TPMI_RH_HIERARCHY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}
   
/* Table 49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type */

TPM_RC
TSS_TPMI_RH_ENABLES_Marshal(const TPMI_RH_ENABLES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(const TPMI_RH_HIERARCHY_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type <IN> */

TPM_RC
TSS_TPMI_RH_PLATFORM_Marshal(const TPMI_RH_PLATFORM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type <IN> */

TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Marshal(const TPMI_RH_ENDORSEMENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type <IN> */

TPM_RC
TSS_TPMI_RH_PROVISION_Marshal(const TPMI_RH_PROVISION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type <IN> */

TPM_RC
TSS_TPMI_RH_CLEAR_Marshal(const TPMI_RH_CLEAR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_NV_AUTH_Marshal(const TPMI_RH_NV_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type <IN> */

TPM_RC
TSS_TPMI_RH_LOCKOUT_Marshal(const TPMI_RH_LOCKOUT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type <IN/OUT> */

TPM_RC
TSS_TPMI_RH_NV_INDEX_Marshal(const TPMI_RH_NV_INDEX *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */

TPM_RC
TSS_TPMI_ALG_HASH_Marshal(const TPMI_ALG_HASH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */

TPM_RC
TSS_TPMI_ALG_SYM_Marshal(const TPMI_ALG_SYM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */

TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Marshal(const TPMI_ALG_SYM_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */

TPM_RC
TSS_TPMI_ALG_SYM_MODE_Marshal(const TPMI_ALG_SYM_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */

TPM_RC
TSS_TPMI_ALG_KDF_Marshal(const TPMI_ALG_KDF *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Marshal(const TPMI_ALG_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 66 - Definition of (TPM_ALG_ID) TPMI_ECC_KEY_EXCHANGE Type */

TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(const TPMI_ECC_KEY_EXCHANGE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
} 

/* Table 67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type */

TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Marshal(const TPMI_ST_COMMAND_TAG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 71 - Definition of (TPM_ALG_ID) TPMI_ALG_MAC_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_MAC_SCHEME_Marshal(const TPMI_ALG_MAC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 72 - Definition of (TPM_ALG_ID) TPMI_ALG_CIPHER_MODE Type */

TPM_RC
TSS_TPMI_ALG_CIPHER_MODE_Marshal(const TPMI_ALG_CIPHER_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
} 

/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_HA_Marshal(const TPMU_HA *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    
    switch (selector) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	if (rc == 0) {
	    rc = TSS_Array_Marshal(&source->sha1[0], SHA1_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	if (rc == 0) {
	    rc = TSS_Array_Marshal(&source->sha256[0], SHA256_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	if (rc == 0) {
	    rc = TSS_Array_Marshal(&source->sha384[0], SHA384_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	if (rc == 0) {
	    rc = TSS_Array_Marshal(&source->sha512[0], SHA512_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM3_256
      case TPM_ALG_SM3_256:
	if (rc == 0) {
	    rc = TSS_Array_Marshal(&source->sm3_256[0], SM3_256_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 71 - Definition of TPMT_HA Structure <IN/OUT> */

TPM_RC
TSS_TPMT_HA_Marshal(const TPMT_HA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_HA_Marshal(&source->digest, written, buffer, size, source->hashAlg);
    }
    return rc;
}

/* Table 72 - Definition of TPM2B_DIGEST Structure */

TPM_RC
TSS_TPM2B_DIGEST_Marshal(const TPM2B_DIGEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 73 - Definition of TPM2B_DATA Structure */

TPM_RC
TSS_TPM2B_DATA_Marshal(const TPM2B_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 74 - Definition of Types for TPM2B_NONCE */

TPM_RC
TSS_TPM2B_NONCE_Marshal(const TPM2B_NONCE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 75 - Definition of Types for TPM2B_AUTH */

TPM_RC
TSS_TPM2B_AUTH_Marshal(const TPM2B_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 76 - Definition of Types for TPM2B_OPERAND */

TPM_RC
TSS_TPM2B_OPERAND_Marshal(const TPM2B_OPERAND *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 77 - Definition of TPM2B_EVENT Structure */

TPM_RC
TSS_TPM2B_EVENT_Marshal(const TPM2B_EVENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 78 - Definition of TPM2B_MAX_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_BUFFER_Marshal(const TPM2B_MAX_BUFFER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 79 - Definition of TPM2B_MAX_NV_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Marshal(const TPM2B_MAX_NV_BUFFER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 80 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_TIMEOUT_Marshal(const TPM2B_TIMEOUT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 81 - Definition of TPM2B_IV Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_IV_Marshal(const TPM2B_IV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 83 - Definition of TPM2B_NAME Structure */

TPM_RC
TSS_TPM2B_NAME_Marshal(const TPM2B_NAME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */

TPM_RC
TSS_TPMS_PCR_SELECTION_Marshal(const TPMS_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->sizeofSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(&source->pcrSelect[0], PCR_SELECT_MAX, written, buffer, size);
    }
    return rc;
}

/* Table 88 - Definition of TPMT_TK_CREATION Structure */

TPM_RC
TSS_TPMT_TK_CREATION_Marshal(const TPMT_TK_CREATION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 89 - Definition of TPMT_TK_VERIFIED Structure */

TPM_RC
TSS_TPMT_TK_VERIFIED_Marshal(const TPMT_TK_VERIFIED *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 90 - Definition of TPMT_TK_AUTH Structure */

TPM_RC
TSS_TPMT_TK_AUTH_Marshal(const TPMT_TK_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */

TPM_RC
TSS_TPMT_TK_HASHCHECK_Marshal(const TPMT_TK_HASHCHECK *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 92 - Definition of TPMS_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_ALG_PROPERTY_Marshal(const TPMS_ALG_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(&source->alg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_ALGORITHM_Marshal(&source->algProperties, written, buffer, size);
    }
    return rc;
}

/* Table 93 - Definition of TPMS_TAGGED_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Marshal(const TPMS_TAGGED_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PT_Marshal(&source->property, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->value, written, buffer, size);
    }
    return rc;
}

/* Table 94 - Definition of TPMS_TAGGED_PCR_SELECT Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Marshal(const TPMS_TAGGED_PCR_SELECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PT_PCR_Marshal(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->sizeofSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshal(&source->pcrSelect[0], PCR_SELECT_MAX, written, buffer, size);
    }
    return rc;
}

/* Table 95 - Definition of TPML_CC Structure */

TPM_RC
TSS_TPML_CC_Marshal(const TPML_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_CC_Marshal(&source->commandCodes[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 96 - Definition of TPML_CCA Structure <OUT> */

TPM_RC
TSS_TPML_CCA_Marshal(const TPML_CCA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMA_CC_Marshal(&source->commandAttributes[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 97 - Definition of TPML_ALG Structure */

TPM_RC
TSS_TPML_ALG_Marshal(const TPML_ALG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_ALG_ID_Marshal(&source->algorithms[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 98 - Definition of TPML_HANDLE Structure <OUT> */

TPM_RC
TSS_TPML_HANDLE_Marshal(const TPML_HANDLE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_HANDLE_Marshal(&source->handle[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 99 - Definition of TPML_DIGEST Structure */

TPM_RC
TSS_TPML_DIGEST_Marshal(const TPML_DIGEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshal(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 100 - Definition of TPML_DIGEST_VALUES Structure */

TPM_RC
TSS_TPML_DIGEST_VALUES_Marshal(const TPML_DIGEST_VALUES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMT_HA_Marshal(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

TPM_RC
TSS_TPML_PCR_SELECTION_Marshal(const TPML_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_PCR_SELECTION_Marshal(&source->pcrSelections[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 103 - Definition of TPML_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_ALG_PROPERTY_Marshal(const TPML_ALG_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_ALG_PROPERTY_Marshal(&source->algProperties[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(const TPML_TAGGED_TPM_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_TAGGED_PROPERTY_Marshal(&source->tpmProperty[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(const TPML_TAGGED_PCR_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_TAGGED_PCR_SELECT_Marshal(&source->pcrProperty[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 106 - Definition of {ECC} TPML_ECC_CURVE Structure <OUT> */

TPM_RC
TSS_TPML_ECC_CURVE_Marshal(const TPML_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_ECC_CURVE_Marshal(&source->eccCurves[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 107 - Definition of TPMU_CAPABILITIES Union <OUT> */

TPM_RC
TSS_TPMU_CAPABILITIES_Marshal(const TPMU_CAPABILITIES *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_CAP_ALGS:
	if (rc == 0) {
	    rc = TSS_TPML_ALG_PROPERTY_Marshal(&source->algorithms, written, buffer, size);
	}
	break;
      case TPM_CAP_HANDLES:
	if (rc == 0) {
	    rc = TSS_TPML_HANDLE_Marshal(&source->handles, written, buffer, size);
	}
	break;
      case TPM_CAP_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CCA_Marshal(&source->command, written, buffer, size);
	}
	break;
      case TPM_CAP_PP_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CC_Marshal(&source->ppCommands, written, buffer, size);
	}
	break;
      case TPM_CAP_AUDIT_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CC_Marshal(&source->auditCommands, written, buffer, size);
	}
	break;
      case TPM_CAP_PCRS:
	if (rc == 0) {
	    rc = TSS_TPML_PCR_SELECTION_Marshal(&source->assignedPCR, written, buffer, size);
	}
	break;
      case TPM_CAP_TPM_PROPERTIES:
	if (rc == 0) {
	    rc = TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(&source->tpmProperties, written, buffer, size);
	}
	break;
      case TPM_CAP_PCR_PROPERTIES:
	if (rc == 0) {
	    rc = TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(&source->pcrProperties, written, buffer, size);
	}
	break;
      case TPM_CAP_ECC_CURVES:
	if (rc == 0) {
	    rc = TSS_TPML_ECC_CURVE_Marshal(&source->eccCurves, written, buffer, size);
	}
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 108 - Definition of TPMS_CAPABILITY_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CAPABILITY_DATA_Marshal(const TPMS_CAPABILITY_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_CAP_Marshal(&source->capability, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_CAPABILITIES_Marshal(&source->data, written, buffer, size, source->capability);
    }
    return rc;
}

/* Table 109 - Definition of TPMS_CLOCK_INFO Structure */

TPM_RC
TSS_TPMS_CLOCK_INFO_Marshal(const TPMS_CLOCK_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->clock, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->resetCount, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->restartCount, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->safe, written, buffer, size);
    }
    return rc;
}

/* Table 110 - Definition of TPMS_TIME_INFO Structure */

TPM_RC
TSS_TPMS_TIME_INFO_Marshal(const TPMS_TIME_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->time, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CLOCK_INFO_Marshal(&source->clockInfo, written, buffer, size);
    }
    return rc;
}
    
/* Table 111 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Marshal(const TPMS_TIME_ATTEST_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_TIME_INFO_Marshal(&source->time, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->firmwareVersion, written, buffer, size);
    }
    return rc;
}

/* Table 112 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CERTIFY_INFO_Marshal(const TPMS_CERTIFY_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->name, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->qualifiedName, written, buffer, size);
    }
    return rc;
}

/* Table 113 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_QUOTE_INFO_Marshal(const TPMS_QUOTE_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->pcrSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->pcrDigest, written, buffer, size);
    }
    return rc;
}

/* Table 114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(const TPMS_COMMAND_AUDIT_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->auditCounter, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(&source->digestAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->auditDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->commandDigest, written, buffer, size);
    }
    return rc;
}

/* Table 115 - Definition of TPMS_SESSION_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Marshal(const TPMS_SESSION_AUDIT_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshal(&source->exclusiveSession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->sessionDigest, written, buffer, size);
    }
    return rc;
}

/* Table 116 - Definition of TPMS_CREATION_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_INFO_Marshal(const TPMS_CREATION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->objectName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->creationHash, written, buffer, size);
    }
    return rc;
}

/* Table 117 - Definition of TPMS_NV_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Marshal(const TPMS_NV_CERTIFY_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->indexName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshal(&source->nvContents, written, buffer, size);
    }
    return rc;
}

/* Table 118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

TPM_RC
TSS_TPMI_ST_ATTEST_Marshal(const TPMI_ST_ATTEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 119 - Definition of TPMU_ATTEST Union <OUT> */

TPM_RC
TSS_TPMU_ATTEST_Marshal(const TPMU_ATTEST  *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	if (rc == 0) {
	    rc = TSS_TPMS_CERTIFY_INFO_Marshal(&source->certify, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_CREATION:
	if (rc == 0) {
	    rc = TSS_TPMS_CREATION_INFO_Marshal(&source->creation, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_QUOTE:
	if (rc == 0) {
	    rc = TSS_TPMS_QUOTE_INFO_Marshal(&source->quote, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	if (rc == 0) {
	    rc = TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(&source->commandAudit, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	if (rc == 0) {
	    rc = TSS_TPMS_SESSION_AUDIT_INFO_Marshal(&source->sessionAudit, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_TIME:
	if (rc == 0) {
	    rc = TSS_TPMS_TIME_ATTEST_INFO_Marshal(&source->time, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_NV:
	if (rc == 0) {
	    rc = TSS_TPMS_NV_CERTIFY_INFO_Marshal(&source->nv, written, buffer, size);
	}
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 120 - Definition of TPMS_ATTEST Structure <OUT> */

TPM_RC
TSS_TPMS_ATTEST_Marshal(const TPMS_ATTEST  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_GENERATED_Marshal(&source->magic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ST_ATTEST_Marshal(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->qualifiedSigner, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->extraData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CLOCK_INFO_Marshal(&source->clockInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->firmwareVersion, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ATTEST_Marshal(&source->attested, written, buffer, size,source->type);
    }
    return rc;
}

/* Table 121 - Definition of TPM2B_ATTEST Structure <OUT> */

TPM_RC
TSS_TPM2B_ATTEST_Marshal(const TPM2B_ATTEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 122 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

TPM_RC
TSS_TPMS_AUTH_COMMAND_Marshal(const TPMS_AUTH_COMMAND *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Marshal(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonce, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_SESSION_Marshal(&source->sessionAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->hmac, written, buffer, size);
    }
    return rc;
}

/* Table 124 - Definition of {AES} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type */

TPM_RC
TSS_TPMI_AES_KEY_BITS_Marshal(const TPMI_AES_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_BITS_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */

TPM_RC
TSS_TPMU_SYM_KEY_BITS_Marshal(const TPMU_SYM_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch(selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	if (rc == 0) {
	    rc = TSS_TPMI_AES_KEY_BITS_Marshal(&source->aes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	if (rc == 0) {
	    rc = TSS_TPMI_SM4_KEY_BITS_Marshal(&source->sm4, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	if (rc == 0) {
	    rc = TSS_TPMI_CAMELLIA_KEY_BITS_Marshal(&source->camellia, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_HASH_Marshal(&source->xorr, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	return rc;
    }
    return rc;
}

/* Table 126 - Definition of TPMU_SYM_MODE Union */

TPM_RC
TSS_TPMU_SYM_MODE_Marshal(const TPMU_SYM_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshal(&source->aes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshal(&source->sm4, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshal(&source->camellia, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 128 - Definition of TPMT_SYM_DEF Structure */

TPM_RC
TSS_TPMT_SYM_DEF_Marshal(const TPMT_SYM_DEF *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SYM_Marshal(&source->algorithm, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_KEY_BITS_Marshal(&source->keyBits, written, buffer, size, source->algorithm);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_MODE_Marshal(&source->mode, written, buffer, size, source->algorithm);
    }
    return rc;
}

/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure */

TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Marshal(const TPMT_SYM_DEF_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SYM_OBJECT_Marshal(&source->algorithm, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_KEY_BITS_Marshal(&source->keyBits, written, buffer, size, source->algorithm);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_MODE_Marshal(&source->mode, written, buffer, size, source->algorithm);
    }
    return rc;
}

/* Table 130 - Definition of TPM2B_SYM_KEY Structure */

TPM_RC
TSS_TPM2B_SYM_KEY_Marshal(const TPM2B_SYM_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 134 - Definition of TPM2B_LABEL Structure */

TPM_RC
TSS_TPM2B_LABEL_Marshal(const TPM2B_LABEL *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 139 - Definition of TPMS_DERIVE Structure */

TPM_RC
TSS_TPMS_DERIVE_Marshal(const TPMS_DERIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_LABEL_Marshal(&source->label, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_LABEL_Marshal(&source->context, written, buffer, size);
    }
    return rc;
}

/* Table 131 - Definition of TPMS_SYMCIPHER_PARMS Structure */

TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Marshal(const TPMS_SYMCIPHER_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshal(&source->sym, written, buffer, size);
    }
    return rc;
}

/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure */

TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Marshal(const TPM2B_SENSITIVE_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Marshal(const TPMS_SENSITIVE_CREATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->userAuth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshal(&source->data, written, buffer, size);
    }
    return rc;
}

/* Table 134 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Marshal(const TPM2B_SENSITIVE_CREATE  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_SENSITIVE_CREATE_Marshal(&source->sensitive, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);	/* backfill 2B size */
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */

TPM_RC
TSS_TPMS_SCHEME_HASH_Marshal(const TPMS_SCHEME_HASH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
    
/* Table 136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

TPM_RC
TSS_TPMS_SCHEME_ECDAA_Marshal(const TPMS_SCHEME_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->count, written, buffer, size);
    }
    return rc;
}

/* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(const TPMI_ALG_KEYEDHASH_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 138 - Definition of Types for HMAC_SIG_SCHEME */

TPM_RC
TSS_TPMS_SCHEME_HMAC_Marshal(const TPMS_SCHEME_HMAC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 139 - Definition of TPMS_SCHEME_XOR Structure */

TPM_RC
TSS_TPMS_SCHEME_XOR_Marshal(const TPMS_SCHEME_XOR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KDF_Marshal(&source->kdf, written, buffer, size);
    }
    return rc;
}

/* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Marshal(const TPMU_SCHEME_KEYEDHASH *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_HMAC_Marshal(&source->hmac, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_XOR_Marshal(&source->xorr, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

TPM_RC
TSS_TPMT_KEYEDHASH_SCHEME_Marshal(const TPMT_KEYEDHASH_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SCHEME_KEYEDHASH_Marshal(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(const TPMS_SIG_SCHEME_RSASSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(const TPMS_SIG_SCHEME_RSAPSS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(const TPMS_SIG_SCHEME_ECDSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Marshal(const TPMS_SIG_SCHEME_SM2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(const TPMS_SIG_SCHEME_ECSCHNORR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(const TPMS_SIG_SCHEME_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_ECDAA_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIG_SCHEME_Marshal(const TPMU_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_SM2_Marshal(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(&source->ecSchnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_HMAC_Marshal(&source->hmac, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}
 
/* Table 145 - Definition of TPMT_SIG_SCHEME Structure */

TPM_RC
TSS_TPMT_SIG_SCHEME_Marshal(const TPMT_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SIG_SCHEME_Marshal(&source->details, written, buffer, size,source->scheme);
    }
    return rc;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Marshal(const TPMS_ENC_SCHEME_OAEP *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Marshal(const TPMS_ENC_SCHEME_RSAES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    source = source;
    written = written;
    buffer = buffer;
    size = size;
    return 0;
}

/* Table 147 - Definition of Types for {ECC} ECC Key Exchange */

TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Marshal(const TPMS_KEY_SCHEME_ECDH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(const TPMS_KEY_SCHEME_ECMQV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_MGF1_Marshal(const TPMS_SCHEME_MGF1 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(const TPMS_SCHEME_KDF1_SP800_56A *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF2_Marshal(const TPMS_SCHEME_KDF2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(const TPMS_SCHEME_KDF1_SP800_108 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_KDF_SCHEME_Marshal(const TPMU_KDF_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_MGF1
      case TPM_ALG_MGF1:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_MGF1_Marshal(&source->mgf1, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_56A
      case TPM_ALG_KDF1_SP800_56A:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(&source->kdf1_SP800_56a, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF2
      case TPM_ALG_KDF2:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF2_Marshal(&source->kdf2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_108
      case TPM_ALG_KDF1_SP800_108:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(&source->kdf1_sp800_108, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}
/* Table 150 - Definition of TPMT_KDF_SCHEME Structure */

TPM_RC
TSS_TPMT_KDF_SCHEME_Marshal(const TPMT_KDF_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KDF_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_KDF_SCHEME_Marshal(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */

TPM_RC
TSS_TPMU_ASYM_SCHEME_Marshal(const TPMU_ASYM_SCHEME  *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	if (rc == 0) {
	    rc = TSS_TPMS_KEY_SCHEME_ECDH_Marshal(&source->ecdh, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	if (rc == 0) {
	    rc = TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(&source->ecmqvh, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_SM2_Marshal(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(&source->ecSchnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	if (rc == 0) {
	    rc = TSS_TPMS_ENC_SCHEME_RSAES_Marshal(&source->rsaes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	if (rc == 0) {
	    rc = TSS_TPMS_ENC_SCHEME_OAEP_Marshal(&source->oaep, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Marshal(const TPMI_ALG_RSA_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

TPM_RC
TSS_TPMT_RSA_SCHEME_Marshal(const TPMT_RSA_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_RSA_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshal(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type */

TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Marshal(const TPMI_ALG_RSA_DECRYPT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

TPM_RC
TSS_TPMT_RSA_DECRYPT_Marshal(const TPMT_RSA_DECRYPT  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_RSA_DECRYPT_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshal(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */

TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(const TPM2B_PUBLIC_KEY_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

TPM_RC
TSS_TPMI_RSA_KEY_BITS_Marshal(const TPMI_RSA_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_BITS_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure */

TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(const TPM2B_PRIVATE_KEY_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure */

TPM_RC
TSS_TPM2B_ECC_PARAMETER_Marshal(const TPM2B_ECC_PARAMETER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 162 - Definition of {ECC} TPMS_ECC_POINT Structure */

TPM_RC
TSS_TPMS_ECC_POINT_Marshal(const TPMS_ECC_POINT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->x, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->y, written, buffer, size);
    }
    return rc;
}

/* Table 163 - Definition of {ECC} TPM2B_ECC_POINT Structure */

TPM_RC
TSS_TPM2B_ECC_POINT_Marshal(const TPM2B_ECC_POINT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_ECC_POINT_Marshal(&source->point, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Marshal(const TPMI_ALG_ECC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

TPM_RC
TSS_TPMI_ECC_CURVE_Marshal(const TPMI_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ECC_CURVE_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

TPM_RC
TSS_TPMT_ECC_SCHEME_Marshal(const TPMT_ECC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_ECC_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshal(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshal(const TPMS_ALGORITHM_DETAIL_ECC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ECC_CURVE_Marshal(&source->curveID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->keySize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_KDF_SCHEME_Marshal(&source->kdf, written, buffer, size);;
    }
    if (rc == 0) {
	rc = TSS_TPMT_ECC_SCHEME_Marshal(&source->sign, written, buffer, size);;
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->p, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->a, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->b, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->gX, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->gY, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->n, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->h, written, buffer, size);
    }
    return rc;
}
    
/* Table 168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

TPM_RC
TSS_TPMS_SIGNATURE_RSA_Marshal(const TPMS_SIGNATURE_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&source->sig, written, buffer, size);
    }
    return rc;
}

/* Table 169 - Definition of Types for {RSA} Signature */

TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Marshal(const TPMS_SIGNATURE_RSASSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_RSA_Marshal(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Marshal(const TPMS_SIGNATURE_RSAPSS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_RSA_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure */

TPM_RC
TSS_TPMS_SIGNATURE_ECC_Marshal(const TPMS_SIGNATURE_ECC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->signatureR, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->signatureS, written, buffer, size);
    }
    return rc;
}
    
/* Table 171 - Definition of Types for {ECC} TPMS_SIGNATURE_ECC */

TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Marshal(const TPMS_SIGNATURE_ECDSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshal(source, written, buffer, size);
    }
    return rc;
}	

TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Marshal(const TPMS_SIGNATURE_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshal(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_SM2_Marshal(const TPMS_SIGNATURE_SM2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshal(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Marshal(const TPMS_SIGNATURE_ECSCHNORR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 172 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIGNATURE_Marshal(const TPMU_SIGNATURE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_RSASSA_Marshal(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_RSAPSS_Marshal(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshal(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshal(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshal(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshal(&source->ecschnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMT_HA_Marshal(&source->hmac, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 173 - Definition of TPMT_SIGNATURE Structure */

TPM_RC
TSS_TPMT_SIGNATURE_Marshal(const TPMT_SIGNATURE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Marshal(&source->sigAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SIGNATURE_Marshal(&source->signature, written, buffer, size, source->sigAlg);
    }
    return rc;
}

/* Table 175 - Definition of TPM2B_ENCRYPTED_SECRET Structure */

TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Marshal(const TPM2B_ENCRYPTED_SECRET *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}
 
/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

TPM_RC
TSS_TPMI_ALG_PUBLIC_Marshal(const TPMI_ALG_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(source, written, buffer, size);
    }
    return rc;
}

/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_ID_Marshal(const TPMU_PUBLIC_ID *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshal(&source->keyedHash, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshal(&source->sym, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&source->rsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPMS_ECC_POINT_Marshal(&source->ecc, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
} 

/* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */

TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Marshal(const TPMS_KEYEDHASH_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_KEYEDHASH_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    return rc;
}

/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */

TPM_RC
TSS_TPMS_RSA_PARMS_Marshal(const TPMS_RSA_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RSA_KEY_BITS_Marshal(&source->keyBits, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->exponent, written, buffer, size);
    }
    return rc;
}
/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure */

TPM_RC
TSS_TPMS_ECC_PARMS_Marshal(const TPMS_ECC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_ECC_SCHEME_Marshal(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshal(&source->curveID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_KDF_SCHEME_Marshal(&source->kdf, written, buffer, size);
    }
    return rc;
}

/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_PARMS_Marshal(const TPMU_PUBLIC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector) 
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPMS_KEYEDHASH_PARMS_Marshal(&source->keyedHashDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPMS_SYMCIPHER_PARMS_Marshal(&source->symDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPMS_RSA_PARMS_Marshal(&source->rsaDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPMS_ECC_PARMS_Marshal(&source->eccDetail, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 183 - Definition of TPMT_PUBLIC_PARMS Structure */

TPM_RC
TSS_TPMT_PUBLIC_PARMS_Marshal(const TPMT_PUBLIC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshal(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshal(&source->parameters, written, buffer, size, source->type);
    }
    return rc;
}

/* Table 184 - Definition of TPMT_PUBLIC Structure */

TPM_RC
TSS_TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshal(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_OBJECT_Marshal(&source->objectAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshal(&source->parameters, written, buffer, size, source->type);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_ID_Marshal(&source->unique, written, buffer, size, source->type);
    }
    return rc;
}

/* Table 184 - Definition of TPMT_PUBLIC Structure - special marshaling for derived object template */

TPM_RC
TSS_TPMT_PUBLIC_D_Marshal(const TPMT_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshal(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_OBJECT_Marshal(&source->objectAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshal(&source->parameters, written, buffer, size, source->type);
    }
    /* if derived from a derivation parent, marshal a TPMS_DERIVE structure */             
    if (rc == 0) {
	rc = TSS_TPMS_DERIVE_Marshal(&source->unique.derive, written, buffer, size);
    }    
    return rc;
}

/* Table 185 - Definition of TPM2B_PUBLIC Structure */

TPM_RC
TSS_TPM2B_PUBLIC_Marshal(const TPM2B_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;
    
    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_Marshal(&source->publicArea, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

TPM_RC
TSS_TPM2B_TEMPLATE_Marshal(const TPM2B_TEMPLATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 187 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(const TPMU_SENSITIVE_COMPOSITE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(&source->rsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPM2B_ECC_PARAMETER_Marshal(&source->ecc, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPM2B_SENSITIVE_DATA_Marshal(&source->bits, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPM2B_SYM_KEY_Marshal(&source->sym, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 188 - Definition of TPMT_SENSITIVE Structure */

TPM_RC
TSS_TPMT_SENSITIVE_Marshal(const TPMT_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshal(&source->sensitiveType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->authValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->seedValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(&source->sensitive, written, buffer, size, source->sensitiveType);
    }
    return rc;
}

/* Table 189 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_SENSITIVE_Marshal(const TPM2B_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;
    
    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SENSITIVE_Marshal(&source->t.sensitiveArea, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 191 - Definition of TPM2B_PRIVATE Structure <IN/OUT, S> */

TPM_RC
TSS_TPM2B_PRIVATE_Marshal(const TPM2B_PRIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 193 - Definition of TPM2B_ID_OBJECT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_ID_OBJECT_Marshal(const TPM2B_ID_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 196 - Definition of (UINT32) TPMA_NV Bits */

TPM_RC
TSS_TPMA_NV_Marshal(const TPMA_NV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 197 - Definition of TPMS_NV_PUBLIC Structure */

TPM_RC
TSS_TPMS_NV_PUBLIC_Marshal(const TPMS_NV_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_NV_Marshal(&source->attributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshal(&source->dataSize, written, buffer, size);
    }
    return rc;
}

/* Table 198 - Definition of TPM2B_NV_PUBLIC Structure */

TPM_RC
TSS_TPM2B_NV_PUBLIC_Marshal(const TPM2B_NV_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
 	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_NV_PUBLIC_Marshal(&source->nvPublic, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 199 - Definition of TPM2B_CONTEXT_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Marshal(const TPM2B_CONTEXT_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 201 - Definition of TPM2B_CONTEXT_DATA Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_DATA_Marshal(const TPM2B_CONTEXT_DATA  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshal(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 202 - Definition of TPMS_CONTEXT Structure */

TPM_RC
TSS_TPMS_CONTEXT_Marshal(const TPMS_CONTEXT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshal(&source->sequence, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_CONTEXT_Marshal(&source->savedHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_CONTEXT_DATA_Marshal(&source->contextBlob, written, buffer, size);
    }
    return rc;
}

/* Table 204 - Definition of TPMS_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_DATA_Marshal(const TPMS_CREATION_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshal(&source->pcrSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->pcrDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_LOCALITY_Marshal(&source->locality, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshal(&source->parentNameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->parentName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->parentQualifiedName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshal(&source->outsideInfo, written, buffer, size);
    }
    return rc;
}

/* Table 205 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPM2B_CREATION_DATA_Marshal(const TPM2B_CREATION_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CREATION_DATA_Marshal(&source->creationData, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshal(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

#endif /* TPM 2.0 */
