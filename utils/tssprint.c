/********************************************************************************/
/*										*/
/*			     Structure Print and Scan Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssprint.c 1147 2018-02-08 23:28:29Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017.					*/
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

#include <tss2/Unmarshal_fp.h>
#include <tss2/tsserror.h>
#include <tss2/tssutils.h>

#include <tss2/tssprint.h>

extern int tssVerbose;

#ifdef TPM_NO_PRINT

/* false to compile out printf */
int tssSwallowRc = 0;
/* function prototype to match the printf prototype */
int TSS_SwallowPrintf(const char *format, ...)
{
    format = format;
    return 0;
}

#endif

/* TSS_Array_Scan() converts a string to a binary array */

uint32_t TSS_Array_Scan(unsigned char **data,	/* output binary, freed by caller */
			size_t *len,
			const char *string)	/* input string */
{
    uint32_t rc = 0;
    size_t strLength;
    
    if (rc == 0) {
	strLength = strlen(string);
	if ((strLength %2) != 0) {
	    if (tssVerbose) printf("TSS_Array_Scan: Error, string length %lu is not even\n",
				   (unsigned long)strLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    if (rc == 0) {
	*len = strLength / 2;		/* safe because already tested for even number of bytes */
        rc = TSS_Malloc(data, (*len) + 8);
    }
    if (rc == 0) {
	unsigned int i;
	for (i = 0 ; i < *len ; i++) {
	    unsigned int tmpint;
	    int irc = sscanf(string + (2*i), "%2x", &tmpint);
	    *((*data)+i) = tmpint;
	    if (irc != 1) {
		if (tssVerbose) printf("TSS_Array_Scan: invalid hexascii\n");
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
    }
    return rc;
}

/* TSS_PrintAll() prints 'string', the length, and then the entire byte array
 */

void TSS_PrintAll(const char *string, const unsigned char* buff, uint32_t length)
{
    TSS_PrintAlli(string, 1, buff, length);
}

/* TSS_PrintAlli() prints 'string', the length, and then the entire byte array
   
   Each line indented 'indent' spaces.
*/

void TSS_PrintAlli(const char *string, unsigned int indent, const unsigned char* buff, uint32_t length)
{
    uint32_t i;
    if (buff != NULL) {
        printf("%*s" "%s length %u\n" "%*s", indent, "", string, length, indent, "");
        for (i = 0 ; i < length ; i++) {
            if (i && !( i % 16 )) {
                printf("\n" "%*s", indent, "");
            }
            printf("%.2x ",buff[i]);
        }
        printf("\n");
    }
    else {
        printf("%*s" "%s null\n", indent, "", string);
    }
    return;
}

/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

void TSS_TPM_ALG_ID_Print(TPM_ALG_ID source, unsigned int indent)
{
    switch (source) {
      case  ALG_RSA_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_RSA\n", indent, "");
	break;
      case  ALG_TDES_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_TDES\n", indent, "");
	break;
      case  ALG_SHA1_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SHA1\n", indent, "");
	break;
      case  ALG_HMAC_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_HMAC\n", indent, "");
	break;
      case  ALG_AES_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_AES\n", indent, "");
	break;
      case  ALG_MGF1_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_MGF1\n", indent, "");
	break;
      case  ALG_KEYEDHASH_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_KEYEDHASH\n", indent, "");
	break;
      case  ALG_XOR_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_XOR\n", indent, "");
	break;
      case  ALG_SHA256_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SHA256\n", indent, "");
	break;
      case  ALG_SHA384_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SHA384\n", indent, "");
	break;
      case  ALG_SHA512_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SHA512\n", indent, "");
	break;
      case  ALG_NULL_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_NULL\n", indent, "");
	break;
      case  ALG_SM3_256_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SM3_256\n", indent, "");
	break;
      case  ALG_SM4_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SM4\n", indent, "");
	break;
      case  ALG_RSASSA_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_RSASSA\n", indent, "");
	break;
      case  ALG_RSAES_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_RSAES\n", indent, "");
	break;
      case  ALG_RSAPSS_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_RSAPSS\n", indent, "");
	break;
      case  ALG_OAEP_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_OAEP\n", indent, "");
	break;
      case  ALG_ECDSA_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECDSA\n", indent, "");
	break;
      case  ALG_ECDH_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECDH\n", indent, "");
	break;
      case  ALG_ECDAA_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECDAA\n", indent, "");
	break;
      case  ALG_SM2_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SM2\n", indent, "");
	break;
      case  ALG_ECSCHNORR_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECSCHNORR\n", indent, "");
	break;
      case  ALG_ECMQV_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECMQV\n", indent, "");
	break;
      case  ALG_KDF1_SP800_56A_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_KDF1_SP800_56A\n", indent, "");
	break;
      case  ALG_KDF2_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_KDF2\n", indent, "");
	break;
      case  ALG_KDF1_SP800_108_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_KDF1_SP800_108\n", indent, "");
	break;
      case  ALG_ECC_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECC\n", indent, "");
	break;
      case  ALG_SYMCIPHER_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_SYMCIPHER\n", indent, "");
	break;
      case  ALG_CAMELLIA_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_CAMELLIA\n", indent, "");
	break;
      case  ALG_CTR_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_CTR\n", indent, "");
	break;
      case  ALG_OFB_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_OFB\n", indent, "");
	break;
      case  ALG_CBC_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_CBC\n", indent, "");
	break;
      case  ALG_CFB_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_CFB\n", indent, "");
	break;
      case  ALG_ECB_VALUE:
	printf("%*s" "TPM_ALG_ID TPM_ALG_ECB\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_ALG_ID value %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

void TSS_TPM_ECC_CURVE_Print(TPM_ECC_CURVE source, unsigned int indent)
{
    switch (source) {
      case TPM_ECC_NONE:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NONE\n", indent, "");
	break;
      case TPM_ECC_NIST_P192:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NIST_P192\n", indent, "");
	break;
      case TPM_ECC_NIST_P224:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NIST_P224\n", indent, "");
	break;
      case TPM_ECC_NIST_P256:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NIST_P256\n", indent, "");
	break;
      case TPM_ECC_NIST_P384:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NIST_P384\n", indent, "");
	break;
      case TPM_ECC_NIST_P521:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_NIST_P521\n", indent, "");
	break;
      case TPM_ECC_BN_P256:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_BN_P256\n", indent, "");
	break;
      case TPM_ECC_BN_P638:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_BN_P638\n", indent, "");
	break;
      case TPM_ECC_SM2_P256:
	printf("%*s" "TPM_ECC_CURVE TPM_ECC_SM2_P256\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_ECC_CURVE value %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 12 - Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */

void TSS_TPM_CC_Print(TPM_CC source, unsigned int indent)
{
    switch (source) {
      case TPM_CC_NV_UndefineSpaceSpecial:
	printf("%*s" "TPM_CC_NV_UndefineSpaceSpecial\n", indent, "");
	break;
      case TPM_CC_EvictControl:
	printf("%*s" "TPM_CC_EvictControl\n", indent, "");
	break;
      case TPM_CC_HierarchyControl:
	printf("%*s" "TPM_CC_HierarchyControl\n", indent, "");
	break;
      case TPM_CC_NV_UndefineSpace:
	printf("%*s" "TPM_CC_NV_UndefineSpace\n", indent, "");
	break;
      case TPM_CC_ChangeEPS:
	printf("%*s" "TPM_CC_ChangeEPS\n", indent, "");
	break;
      case TPM_CC_ChangePPS:
	printf("%*s" "TPM_CC_ChangePPS\n", indent, "");
	break;
      case TPM_CC_Clear:
	printf("%*s" "TPM_CC_Clear\n", indent, "");
	break;
      case TPM_CC_ClearControl:
	printf("%*s" "TPM_CC_ClearControl\n", indent, "");
	break;
      case TPM_CC_ClockSet:
	printf("%*s" "TPM_CC_ClockSet\n", indent, "");
	break;
      case TPM_CC_HierarchyChangeAuth:
	printf("%*s" "TPM_CC_HierarchyChangeAuth\n", indent, "");
	break;
      case TPM_CC_NV_DefineSpace:
	printf("%*s" "TPM_CC_NV_DefineSpace\n", indent, "");
	break;
      case TPM_CC_PCR_Allocate:
	printf("%*s" "TPM_CC_PCR_Allocate\n", indent, "");
	break;
      case TPM_CC_PCR_SetAuthPolicy:
	printf("%*s" "TPM_CC_PCR_SetAuthPolicy\n", indent, "");
	break;
      case TPM_CC_PP_Commands:
	printf("%*s" "TPM_CC_PP_Commands\n", indent, "");
	break;
      case TPM_CC_SetPrimaryPolicy:
	printf("%*s" "TPM_CC_SetPrimaryPolicy\n", indent, "");
	break;
#if 0
      case TPM_CC_FieldUpgradeStart:
	printf("%*s" "TPM_CC_FieldUpgradeStart\n", indent, "");
	break;
#endif
      case TPM_CC_ClockRateAdjust:
	printf("%*s" "TPM_CC_ClockRateAdjust\n", indent, "");
	break;
      case TPM_CC_CreatePrimary:
	printf("%*s" "TPM_CC_CreatePrimary\n", indent, "");
	break;
      case TPM_CC_NV_GlobalWriteLock:
	printf("%*s" "TPM_CC_NV_GlobalWriteLock\n", indent, "");
	break;
      case TPM_CC_GetCommandAuditDigest:
	printf("%*s" "TPM_CC_GetCommandAuditDigest\n", indent, "");
	break;
      case TPM_CC_NV_Increment:
	printf("%*s" "TPM_CC_NV_Increment\n", indent, "");
	break;
      case TPM_CC_NV_SetBits:
	printf("%*s" "TPM_CC_NV_SetBits\n", indent, "");
	break;
      case TPM_CC_NV_Extend:
	printf("%*s" "TPM_CC_NV_Extend\n", indent, "");
	break;
      case TPM_CC_NV_Write:
	printf("%*s" "TPM_CC_NV_Write\n", indent, "");
	break;
      case TPM_CC_NV_WriteLock:
	printf("%*s" "TPM_CC_NV_WriteLock\n", indent, "");
	break;
      case TPM_CC_DictionaryAttackLockReset:
	printf("%*s" "TPM_CC_DictionaryAttackLockReset\n", indent, "");
	break;
      case TPM_CC_DictionaryAttackParameters:
	printf("%*s" "TPM_CC_DictionaryAttackParameters\n", indent, "");
	break;
      case TPM_CC_NV_ChangeAuth:
	printf("%*s" "TPM_CC_NV_ChangeAuth\n", indent, "");
	break;
      case TPM_CC_PCR_Event:
	printf("%*s" "TPM_CC_PCR_Event\n", indent, "");
	break;
      case TPM_CC_PCR_Reset:
	printf("%*s" "TPM_CC_PCR_Reset\n", indent, "");
	break;
      case TPM_CC_SequenceComplete:
	printf("%*s" "TPM_CC_SequenceComplete\n", indent, "");
	break;
      case TPM_CC_SetAlgorithmSet:
	printf("%*s" "TPM_CC_SetAlgorithmSet\n", indent, "");
	break;
      case TPM_CC_SetCommandCodeAuditStatus:
	printf("%*s" "TPM_CC_SetCommandCodeAuditStatus\n", indent, "");
	break;
#if 0
      case TPM_CC_FieldUpgradeData:
	printf("%*s" "TPM_CC_FieldUpgradeData\n", indent, "");
	break;
#endif
      case TPM_CC_IncrementalSelfTest:
	printf("%*s" "TPM_CC_IncrementalSelfTest\n", indent, "");
	break;
      case TPM_CC_SelfTest:
	printf("%*s" "TPM_CC_SelfTest\n", indent, "");
	break;
      case TPM_CC_Startup:
	printf("%*s" "TPM_CC_Startup\n", indent, "");
	break;
      case TPM_CC_Shutdown:
	printf("%*s" "TPM_CC_Shutdown\n", indent, "");
	break;
      case TPM_CC_StirRandom:
	printf("%*s" "TPM_CC_StirRandom\n", indent, "");
	break;
      case TPM_CC_ActivateCredential:
	printf("%*s" "TPM_CC_ActivateCredential\n", indent, "");
	break;
      case TPM_CC_Certify:
	printf("%*s" "TPM_CC_Certify\n", indent, "");
	break;
      case TPM_CC_PolicyNV:
	printf("%*s" "TPM_CC_PolicyNV\n", indent, "");
	break;
      case TPM_CC_CertifyCreation:
	printf("%*s" "TPM_CC_CertifyCreation\n", indent, "");
	break;
      case TPM_CC_Duplicate:
	printf("%*s" "TPM_CC_Duplicate\n", indent, "");
	break;
      case TPM_CC_GetTime:
	printf("%*s" "TPM_CC_GetTime\n", indent, "");
	break;
      case TPM_CC_GetSessionAuditDigest:
	printf("%*s" "TPM_CC_GetSessionAuditDigest\n", indent, "");
	break;
      case TPM_CC_NV_Read:
	printf("%*s" "TPM_CC_NV_Read\n", indent, "");
	break;
      case TPM_CC_NV_ReadLock:
	printf("%*s" "TPM_CC_NV_ReadLock\n", indent, "");
	break;
      case TPM_CC_ObjectChangeAuth:
	printf("%*s" "TPM_CC_ObjectChangeAuth\n", indent, "");
	break;
      case TPM_CC_PolicySecret:
	printf("%*s" "TPM_CC_PolicySecret\n", indent, "");
	break;
      case TPM_CC_Rewrap:
	printf("%*s" "TPM_CC_Rewrap\n", indent, "");
	break;
      case TPM_CC_Create:
	printf("%*s" "TPM_CC_Create\n", indent, "");
	break;
      case TPM_CC_ECDH_ZGen:
	printf("%*s" "TPM_CC_ECDH_ZGen\n", indent, "");
	break;
      case TPM_CC_HMAC:
	printf("%*s" "TPM_CC_HMAC\n", indent, "");
	break;
#if 0
      case TPM_CC_MAC:
	printf("%*s" "TPM_CC_MAC\n", indent, "");
	break;
#endif
      case TPM_CC_Import:
	printf("%*s" "TPM_CC_Import\n", indent, "");
	break;
      case TPM_CC_Load:
	printf("%*s" "TPM_CC_Load\n", indent, "");
	break;
      case TPM_CC_Quote:
	printf("%*s" "TPM_CC_Quote\n", indent, "");
	break;
      case TPM_CC_RSA_Decrypt:
	printf("%*s" "TPM_CC_RSA_Decrypt\n", indent, "");
	break;
      case TPM_CC_HMAC_Start:
	printf("%*s" "TPM_CC_HMAC_Start\n", indent, "");
	break;
#if 0
      case TPM_CC_MAC_Start:
	printf("%*s" "TPM_CC_MAC_Start\n", indent, "");
	break;
#endif
      case TPM_CC_SequenceUpdate:
	printf("%*s" "TPM_CC_SequenceUpdate\n", indent, "");
	break;
      case TPM_CC_Sign:
	printf("%*s" "TPM_CC_Sign\n", indent, "");
	break;
      case TPM_CC_Unseal:
	printf("%*s" "TPM_CC_Unseal\n", indent, "");
	break;
      case TPM_CC_PolicySigned:
	printf("%*s" "TPM_CC_PolicySigned\n", indent, "");
	break;
      case TPM_CC_ContextLoad:
	printf("%*s" "TPM_CC_ContextLoad\n", indent, "");
	break;
      case TPM_CC_ContextSave:
	printf("%*s" "TPM_CC_ContextSave\n", indent, "");
	break;
      case TPM_CC_ECDH_KeyGen:
	printf("%*s" "TPM_CC_ECDH_KeyGen\n", indent, "");
	break;
      case TPM_CC_EncryptDecrypt:
	printf("%*s" "TPM_CC_EncryptDecrypt\n", indent, "");
	break;
      case TPM_CC_FlushContext:
	printf("%*s" "TPM_CC_FlushContext\n", indent, "");
	break;
      case TPM_CC_LoadExternal:
	printf("%*s" "TPM_CC_LoadExternal\n", indent, "");
	break;
      case TPM_CC_MakeCredential:
	printf("%*s" "TPM_CC_MakeCredential\n", indent, "");
	break;
      case TPM_CC_NV_ReadPublic:
	printf("%*s" "TPM_CC_NV_ReadPublic\n", indent, "");
	break;
      case TPM_CC_PolicyAuthorize:
	printf("%*s" "TPM_CC_PolicyAuthorize\n", indent, "");
	break;
      case TPM_CC_PolicyAuthValue:
	printf("%*s" "TPM_CC_PolicyAuthValue\n", indent, "");
	break;
      case TPM_CC_PolicyCommandCode:
	printf("%*s" "TPM_CC_PolicyCommandCode\n", indent, "");
	break;
      case TPM_CC_PolicyCounterTimer:
	printf("%*s" "TPM_CC_PolicyCounterTimer\n", indent, "");
	break;
      case TPM_CC_PolicyCpHash:
	printf("%*s" "TPM_CC_PolicyCpHash\n", indent, "");
	break;
      case TPM_CC_PolicyLocality:
	printf("%*s" "TPM_CC_PolicyLocality\n", indent, "");
	break;
      case TPM_CC_PolicyNameHash:
	printf("%*s" "TPM_CC_PolicyNameHash\n", indent, "");
	break;
      case TPM_CC_PolicyOR:
	printf("%*s" "TPM_CC_PolicyOR\n", indent, "");
	break;
      case TPM_CC_PolicyTicket:
	printf("%*s" "TPM_CC_PolicyTicket\n", indent, "");
	break;
      case TPM_CC_ReadPublic:
	printf("%*s" "TPM_CC_ReadPublic\n", indent, "");
	break;
      case TPM_CC_RSA_Encrypt:
	printf("%*s" "TPM_CC_RSA_Encrypt\n", indent, "");
	break;
      case TPM_CC_StartAuthSession:
	printf("%*s" "TPM_CC_StartAuthSession\n", indent, "");
	break;
      case TPM_CC_VerifySignature:
	printf("%*s" "TPM_CC_VerifySignature\n", indent, "");
	break;
      case TPM_CC_ECC_Parameters:
	printf("%*s" "TPM_CC_ECC_Parameters\n", indent, "");
	break;
#if 0
      case TPM_CC_FirmwareRead:
	printf("%*s" "TPM_CC_FirmwareRead\n", indent, "");
	break;
#endif
      case TPM_CC_GetCapability:
	printf("%*s" "TPM_CC_GetCapability\n", indent, "");
	break;
      case TPM_CC_GetRandom:
	printf("%*s" "TPM_CC_GetRandom\n", indent, "");
	break;
      case TPM_CC_GetTestResult:
	printf("%*s" "TPM_CC_GetTestResult\n", indent, "");
	break;
      case TPM_CC_Hash:
	printf("%*s" "TPM_CC_Hash\n", indent, "");
	break;
      case TPM_CC_PCR_Read:
	printf("%*s" "TPM_CC_PCR_Read\n", indent, "");
	break;
      case TPM_CC_PolicyPCR:
	printf("%*s" "TPM_CC_PolicyPCR\n", indent, "");
	break;
      case TPM_CC_PolicyRestart:
	printf("%*s" "TPM_CC_PolicyRestart\n", indent, "");
	break;
      case TPM_CC_ReadClock:
	printf("%*s" "TPM_CC_ReadClock\n", indent, "");
	break;
      case TPM_CC_PCR_Extend:
	printf("%*s" "TPM_CC_PCR_Extend\n", indent, "");
	break;
      case TPM_CC_PCR_SetAuthValue:
	printf("%*s" "TPM_CC_PCR_SetAuthValue\n", indent, "");
	break;
      case TPM_CC_NV_Certify:
	printf("%*s" "TPM_CC_NV_Certify\n", indent, "");
	break;
      case TPM_CC_EventSequenceComplete:
	printf("%*s" "TPM_CC_EventSequenceComplete\n", indent, "");
	break;
      case TPM_CC_HashSequenceStart:
	printf("%*s" "TPM_CC_HashSequenceStart\n", indent, "");
	break;
      case TPM_CC_PolicyPhysicalPresence:
	printf("%*s" "TPM_CC_PolicyPhysicalPresence\n", indent, "");
	break;
      case TPM_CC_PolicyDuplicationSelect:
	printf("%*s" "TPM_CC_PolicyDuplicationSelect\n", indent, "");
	break;
      case TPM_CC_PolicyGetDigest:
	printf("%*s" "TPM_CC_PolicyGetDigest\n", indent, "");
	break;
      case TPM_CC_TestParms:
	printf("%*s" "TPM_CC_TestParms\n", indent, "");
	break;
      case TPM_CC_Commit:
	printf("%*s" "TPM_CC_Commit\n", indent, "");
	break;
      case TPM_CC_PolicyPassword:
	printf("%*s" "TPM_CC_PolicyPassword\n", indent, "");
	break;
      case TPM_CC_ZGen_2Phase:
	printf("%*s" "TPM_CC_ZGen_2Phase\n", indent, "");
	break;
      case TPM_CC_EC_Ephemeral:
	printf("%*s" "TPM_CC_EC_Ephemeral\n", indent, "");
	break;
      case TPM_CC_PolicyNvWritten:
	printf("%*s" "TPM_CC_PolicyNvWritten\n", indent, "");
	break;
      case TPM_CC_PolicyTemplate:
	printf("%*s" "TPM_CC_PolicyTemplate\n", indent, "");
	break;
      case TPM_CC_CreateLoaded:
	printf("%*s" "TPM_CC_CreateLoaded\n", indent, "");
	break;
      case TPM_CC_PolicyAuthorizeNV:
	printf("%*s" "TPM_CC_PolicyAuthorizeNV\n", indent, "");
	break;
      case TPM_CC_EncryptDecrypt2:
	printf("%*s" "TPM_CC_EncryptDecrypt2\n", indent, "");
	break;
#if 0
      case TPM_CC_AC_GetCapability:
	printf("%*s" "TPM_CC_AC_GetCapability\n", indent, "");
	break;
      case TPM_CC_AC_Send:
	printf("%*s" "TPM_CC_AC_Send\n", indent, "");
	break;
      case TPM_CC_Policy_AC_SendSelect:
	printf("%*s" "TPM_CC_Policy_AC_SendSelect\n", indent, "");
	break;
#endif
      default:
	printf("%*s" "TPM_CC value %08x unknown\n", indent, "", source);
    }
    return;
}

/* Table 17 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

void TSS_TPM_CLOCK_ADJUST_Print(TPM_CLOCK_ADJUST source, unsigned int indent)
{
    switch (source) {
      case TPM_CLOCK_COARSE_SLOWER:
	printf("%*s" "TPM_CLOCK_COARSE_SLOWER\n", indent, "");
	break;
      case TPM_CLOCK_MEDIUM_SLOWER:
	printf("%*s" "TPM_CLOCK_MEDIUM_SLOWER\n", indent, "");
	break;
      case TPM_CLOCK_FINE_SLOWER:
	printf("%*s" "TPM_CLOCK_FINE_SLOWER\n", indent, "");
	break;
      case TPM_CLOCK_NO_CHANGE:
	printf("%*s" "TPM_CLOCK_NO_CHANGE\n", indent, "");
	break;
      case TPM_CLOCK_FINE_FASTER:
	printf("%*s" "TPM_CLOCK_FINE_FASTER\n", indent, "");
	break;
      case TPM_CLOCK_MEDIUM_FASTER:
	printf("%*s" "TPM_CLOCK_MEDIUM_FASTER\n", indent, "");
	break;
      case TPM_CLOCK_COARSE_FASTER:
	printf("%*s" "TPM_CLOCK_COARSE_FASTER\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_CLOCK_ADJUST value %d unknown\n", indent, "", source);
    }
    return;
}

/* Table 18 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

void TSS_TPM_EO_Print(TPM_EO source, unsigned int indent) 
{
    switch (source) {
      case TPM_EO_EQ:
	printf("%*s" "TPM_EO_EQ\n", indent, "");
	break;
      case TPM_EO_NEQ:
	printf("%*s" "TPM_EO_NEQ\n", indent, "");
	break;
      case TPM_EO_SIGNED_GT:
	printf("%*s" "TPM_EO_SIGNED_GT\n", indent, "");
	break;
      case TPM_EO_UNSIGNED_GT:
	printf("%*s" "TPM_EO_UNSIGNED_GT\n", indent, "");
	break;
      case TPM_EO_SIGNED_LT:
	printf("%*s" "TPM_EO_SIGNED_LT\n", indent, "");
	break;
      case TPM_EO_UNSIGNED_LT:
	printf("%*s" "TPM_EO_UNSIGNED_LT\n", indent, "");
	break;
      case TPM_EO_SIGNED_GE:
	printf("%*s" "TPM_EO_SIGNED_GE\n", indent, "");
	break;
      case TPM_EO_UNSIGNED_GE:
	printf("%*s" "TPM_EO_UNSIGNED_GE\n", indent, "");
	break;
      case TPM_EO_SIGNED_LE:
	printf("%*s" "TPM_EO_SIGNED_LE\n", indent, "");
	break;
      case TPM_EO_UNSIGNED_LE:
	printf("%*s" "TPM_EO_UNSIGNED_LE\n", indent, "");
	break;
      case TPM_EO_BITSET:
	printf("%*s" "TPM_EO_BITSET\n", indent, "");
	break;
      case TPM_EO_BITCLEAR:
	printf("%*s" "TPM_EO_BITCLEAR\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_EO value %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 19 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

void TSS_TPM_ST_Print(TPM_ST source, unsigned int indent) 
{
    switch (source) {
      case TPM_ST_RSP_COMMAND:
	printf("%*s" "TPM_ST_RSP_COMMAND\n", indent, "");
	break;
      case TPM_ST_NULL:
	printf("%*s" "TPM_ST_NULL\n", indent, "");
	break;
      case TPM_ST_NO_SESSIONS:
	printf("%*s" "TPM_ST_NO_SESSIONS\n", indent, "");
	break;
      case TPM_ST_SESSIONS:
	printf("%*s" "TPM_ST_SESSIONS\n", indent, "");
	break;
      case TPM_ST_ATTEST_NV:
	printf("%*s" "TPM_ST_ATTEST_NV\n", indent, "");
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	printf("%*s" "TPM_ST_ATTEST_COMMAND_AUDIT\n", indent, "");
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	printf("%*s" "TPM_ST_ATTEST_SESSION_AUDIT\n", indent, "");
	break;
      case TPM_ST_ATTEST_CERTIFY:
	printf("%*s" "TPM_ST_ATTEST_CERTIFY\n", indent, "");
	break;
      case TPM_ST_ATTEST_QUOTE:
	printf("%*s" "TPM_ST_ATTEST_QUOTE\n", indent, "");
	break;
      case TPM_ST_ATTEST_TIME:
	printf("%*s" "TPM_ST_ATTEST_TIME\n", indent, "");
	break;
      case TPM_ST_ATTEST_CREATION:
	printf("%*s" "TPM_ST_ATTEST_CREATION\n", indent, "");
	break;
      case TPM_ST_CREATION:
	printf("%*s" "TPM_ST_CREATION\n", indent, "");
	break;
      case TPM_ST_VERIFIED:
	printf("%*s" "TPM_ST_VERIFIED\n", indent, "");
	break;
      case TPM_ST_AUTH_SECRET:
	printf("%*s" "TPM_ST_AUTH_SECRET\n", indent, "");
	break;
      case TPM_ST_HASHCHECK:
	printf("%*s" "TPM_ST_HASHCHECK\n", indent, "");
	break;
      case TPM_ST_AUTH_SIGNED:
	printf("%*s" "TPM_ST_AUTH_SIGNED\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_ST value %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 20 - Definition of (UINT16) TPM_SU Constants <IN> */

void TSS_TPM_SU_Print(TPM_SU source, unsigned int indent) 
{
    switch (source) {
      case TPM_SU_CLEAR:
	printf("%*s" "TPM_SU_CLEAR\n", indent, "");
	break;
      case TPM_SU_STATE:
	printf("%*s" "TPM_SU_STATE\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_SU value %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 21 - Definition of (UINT8) TPM_SE Constants <IN> */

void TSS_TPM_SE_Print(TPM_SE source, unsigned int indent)
{
    switch (source) {
      case TPM_SE_HMAC:
	printf("%*s" "TPM_SE_HMAC\n", indent, "");
	break;
      case TPM_SE_POLICY:
	printf("%*s" "TPM_SE_POLICY\n", indent, "");
	break;
      case TPM_SE_TRIAL:
	printf("%*s" "TPM_SE_TRIAL\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_SE value %02x unknown\n", indent, "", source);
    }
    return;
}

/* Table 22 - Definition of (UINT32) TPM_CAP Constants */

void TSS_TPM_CAP_Print(TPM_CAP source, unsigned int indent)
{
    switch (source) {
     case TPM_CAP_ALGS:
	printf("%*s" "TPM_CAP_ALGS\n", indent, "");
	break;
      case TPM_CAP_HANDLES:
	printf("%*s" "TPM_CAP_HANDLES\n", indent, "");
	break;
      case TPM_CAP_COMMANDS:
	printf("%*s" "TPM_CAP_COMMANDS\n", indent, "");
	break;
      case TPM_CAP_PP_COMMANDS:
	printf("%*s" "TPM_CAP_PP_COMMANDS\n", indent, "");
	break;
      case TPM_CAP_AUDIT_COMMANDS:
	printf("%*s" "TPM_CAP_AUDIT_COMMANDS\n", indent, "");
	break;
      case TPM_CAP_PCRS:
	printf("%*s" "TPM_CAP_PCRS\n", indent, "");
	break;
      case TPM_CAP_TPM_PROPERTIES:
	printf("%*s" "TPM_CAP_TPM_PROPERTIES\n", indent, "");
	break;
      case TPM_CAP_PCR_PROPERTIES:
	printf("%*s" "TPM_CAP_PCR_PROPERTIES\n", indent, "");
	break;
      case TPM_CAP_ECC_CURVES:
	printf("%*s" "TPM_CAP_ECC_CURVES\n", indent, "");
	break;
      case TPM_CAP_AUTH_POLICIES:
	printf("%*s" "TPM_CAP_AUTH_POLICIES\n", indent, "");
	break;
      case TPM_CAP_VENDOR_PROPERTY:
	printf("%*s" "TPM_CAP_VENDOR_PROPERTY\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_CAP value %08x unknown\n", indent, "", source);
    }
    return;
}

/* Table 26 - Definition of Types for Handles */


void TSS_TPM_HANDLE_Print(TPM_HANDLE source, unsigned int indent)
{
    switch (source) {
      case TPM_RH_SRK:
	printf("%*s" "TPM_RH_SRK\n", indent, "");
	break;
      case TPM_RH_OWNER:
	printf("%*s" "TPM_RH_OWNER\n", indent, "");
	break;
      case TPM_RH_REVOKE:
	printf("%*s" "TPM_RH_REVOKE\n", indent, "");
	break;
      case TPM_RH_TRANSPORT:
	printf("%*s" "TPM_RH_TRANSPORT\n", indent, "");
	break;
      case TPM_RH_OPERATOR:
	printf("%*s" "TPM_RH_OPERATOR\n", indent, "");
	break;
      case TPM_RH_ADMIN:
	printf("%*s" "TPM_RH_ADMIN\n", indent, "");
	break;
      case TPM_RH_EK:
	printf("%*s" "TPM_RH_EK\n", indent, "");
	break;
      case TPM_RH_NULL:
	printf("%*s" "TPM_RH_NULL\n", indent, "");
	break;
      case TPM_RH_UNASSIGNED:
	printf("%*s" "TPM_RH_UNASSIGNED\n", indent, "");
	break;
      case TPM_RS_PW:
	printf("%*s" "TPM_RS_PW\n", indent, "");
	break;
      case TPM_RH_LOCKOUT:
	printf("%*s" "TPM_RH_LOCKOUT\n", indent, "");
	break;
      case TPM_RH_ENDORSEMENT:
	printf("%*s" "TPM_RH_ENDORSEMENT\n", indent, "");
	break;
      case TPM_RH_PLATFORM:
	printf("%*s" "TPM_RH_PLATFORM\n", indent, "");
	break;
      case TPM_RH_PLATFORM_NV:
	printf("%*s" "TPM_RH_PLATFORM_NV\n", indent, "");
	break;
      default:
	printf("%*s" "TPM_HANDLE %08x\n", indent, "", source);
    }
    return;
}

/* Table 30 - Definition of (UINT32) TPMA_ALGORITHM Bits */

void TSS_TPM_TPMA_ALGORITHM_Print(TPMA_ALGORITHM source, unsigned int indent)
{
    if (source.val & TPMA_ALGORITHM_ASYMMETRIC) printf("%*s" "TPMA_ALGORITHM: asymmetric\n", indent, "");
    if (source.val & TPMA_ALGORITHM_SYMMETRIC) printf("%*s" "TPMA_ALGORITHM: symmetric\n", indent, "");
    if (source.val & TPMA_ALGORITHM_HASH) printf("%*s" "TPMA_ALGORITHM: hash\n", indent, "");
    if (source.val & TPMA_ALGORITHM_OBJECT) printf("%*s" "TPMA_ALGORITHM: object\n", indent, "");
    if (source.val & TPMA_ALGORITHM_SIGNING) printf("%*s" "TPMA_ALGORITHM: signing\n", indent, "");
    if (source.val & TPMA_ALGORITHM_ENCRYPTING) printf("%*s" "TPMA_ALGORITHM: encrypting\n", indent, "");
    if (source.val & TPMA_ALGORITHM_METHOD) printf("%*s" "TPMA_ALGORITHM: method\n", indent, "");
    return;
}

/* Table 31 - Definition of (UINT32) TPMA_OBJECT Bits */

void TSS_TPMA_OBJECT_Print(TPMA_OBJECT source, unsigned int indent)
{
    if (source.val & TPMA_OBJECT_FIXEDTPM) printf("%*s" "TPMA_OBJECT: fixedTpm\n", indent, "");
    if (source.val & TPMA_OBJECT_STCLEAR) printf("%*s" "TPMA_OBJECT: stClear\n", indent, "");
    if (source.val & TPMA_OBJECT_FIXEDPARENT) printf("%*s" "TPMA_OBJECT: fixedParent\n", indent, "");
    if (source.val & TPMA_OBJECT_SENSITIVEDATAORIGIN) printf("%*s" "TPMA_OBJECT: sensitiveDataOrigin\n", indent, "");
    if (source.val & TPMA_OBJECT_USERWITHAUTH) printf("%*s" "TPMA_OBJECT: userWithAuth\n", indent, "");
    if (source.val & TPMA_OBJECT_ADMINWITHPOLICY) printf("%*s" "TPMA_OBJECT: adminWithPolicy\n", indent, "");
    if (source.val & TPMA_OBJECT_NODA) printf("%*s" "TPMA_OBJECT: noDA\n", indent, "");
    if (source.val & TPMA_OBJECT_ENCRYPTEDDUPLICATION) printf("%*s" "TPMA_OBJECT: encryptedDuplication\n", indent, "");
    if (source.val & TPMA_OBJECT_RESTRICTED) printf("%*s" "TPMA_OBJECT: restricted\n", indent, "");
    if (source.val & TPMA_OBJECT_DECRYPT) printf("%*s" "TPMA_OBJECT: decrypt\n", indent, "");
    if (source.val & TPMA_OBJECT_SIGN) printf("%*s" "TPMA_OBJECT: sign\n", indent, "");
    return;
}

/* Table 33 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

void TSS_TPMA_LOCALITY_Print(TPMA_LOCALITY source, unsigned int indent)
{
    if (source.val & TPMA_LOCALITY_ZERO) printf("%*s" "TPMA_LOCALITY: zero\n", indent, "");
    if (source.val & TPMA_LOCALITY_ONE) printf("%*s" "TPMA_LOCALITY: one\n", indent, "");
    if (source.val & TPMA_LOCALITY_TWO) printf("%*s" "TPMA_LOCALITY: two\n", indent, "");
    if (source.val & TPMA_LOCALITY_THREE) printf("%*s" "TPMA_LOCALITY: three\n", indent, "");
    if (source.val & TPMA_LOCALITY_FOUR) printf("%*s" "TPMA_LOCALITY: four\n", indent, "");
    if (source.val & TPMA_LOCALITY_EXTENDED) printf("%*s" "TPMA_LOCALITY: extended\n", indent, "");
    return;
}

/* Table 32 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

void TSS_TPMA_SESSION_Print(TPMA_SESSION source, unsigned int indent)
{
    
    if (source.val & TPMA_SESSION_CONTINUESESSION) printf("%*s" "TPMA_SESSION: continue\n", indent, "");
    if (source.val & TPMA_SESSION_AUDITEXCLUSIVE) printf("%*s" "TPMA_SESSION: auditexclusive\n", indent, ""); 
    if (source.val & TPMA_SESSION_AUDITRESET) printf("%*s" "TPMA_SESSION: auditreset\n", indent, ""); 
    if (source.val & TPMA_SESSION_DECRYPT) printf("%*s" "TPMA_SESSION: decrypt\n", indent, ""); 
    if (source.val & TPMA_SESSION_ENCRYPT) printf("%*s" "TPMA_SESSION: encrypt\n", indent, ""); 
    if (source.val & TPMA_SESSION_AUDIT) printf("%*s" "TPMA_SESSION: audit\n", indent, ""); 
    return;
}

/* Table 34 - Definition of (UINT32) TPMA_PERMANENT Bits <OUT> */

void TSS_TPMA_PERMANENT_Print(TPMA_PERMANENT source, unsigned int indent)
{
    if (source.val & TPMA_PERMANENT_OWNERAUTHSET) printf("%*s" "TPMA_PERMANENT: ownerAuthSet\n", indent, "");
    if (source.val & TPMA_PERMANENT_ENDORSEMENTAUTHSET) printf("%*s" "TPMA_PERMANENT: endorsementAuthSet\n", indent, "");
    if (source.val & TPMA_PERMANENT_LOCKOUTAUTHSET) printf("%*s" "TPMA_PERMANENT: lockoutAuthSet\n", indent, "");
    if (source.val & TPMA_PERMANENT_DISABLECLEAR) printf("%*s" "TPMA_PERMANENT: disableClear\n", indent, "");
    if (source.val & TPMA_PERMANENT_INLOCKOUT) printf("%*s" "TPMA_PERMANENT: inLockout\n", indent, "");
    if (source.val & TPMA_PERMANENT_TPMGENERATEDEPS) printf("%*s" "TPMA_PERMANENT: tpmGeneratedEPS\n", indent, "");
    return;
}

/* Table 35 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits <OUT> */

void TSS_TPMA_STARTUP_CLEAR_Print(TPMA_STARTUP_CLEAR source, unsigned int indent)
{
    if (source.val & TPMA_STARTUP_CLEAR_PHENABLE) printf("%*s" "TPMA_STARTUP_CLEAR: phEnable\n", indent, "");
    if (source.val & TPMA_STARTUP_CLEAR_SHENABLE) printf("%*s" "TPMA_STARTUP_CLEAR: shEnable\n", indent, "");
    if (source.val & TPMA_STARTUP_CLEAR_EHENABLE) printf("%*s" "TPMA_STARTUP_CLEAR: ehEnable\n", indent, "");
    if (source.val & TPMA_STARTUP_CLEAR_PHENABLENV) printf("%*s" "TPMA_STARTUP_CLEAR: phEnableNV\n", indent, "");
    if (source.val & TPMA_STARTUP_CLEAR_ORDERLY) printf("%*s" "TPMA_STARTUP_CLEAR: orderly\n", indent, "");
    return;
}

/* Table 36 - Definition of (UINT32) TPMA_MEMORY Bits <Out> */

void TSS_TPMA_MEMORY_Print(TPMA_MEMORY source, unsigned int indent)
{
    if (source.val & TPMA_MEMORY_SHAREDRAM) printf("%*s" "TPMA_MEMORY: sharedRAM\n", indent, "");
    if (source.val & TPMA_MEMORY_SHAREDNV) printf("%*s" "TPMA_MEMORY: sharedNV\n", indent, "");
    if (source.val & TPMA_MEMORY_OBJECTCOPIEDTORAM) printf("%*s" "TPMA_MEMORY: objectCopiedToRam\n", indent, "");
    return;
}

/* Table 75 - Definition of TPMU_HA Union <IN/OUT, S> */


void TSS_TPMU_HA_Print(TPMU_HA *source, uint32_t selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	TSS_PrintAlli("sha1", indent, source->sha1, SHA1_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	TSS_PrintAlli("sha256", indent, source->sha256, SHA256_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	TSS_PrintAlli("sha384", indent, source->sha384, SHA384_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	TSS_PrintAlli("sha512", indent, source->sha512, SHA512_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SM3_256
      case TPM_ALG_SM3_256:
	TSS_PrintAlli("sm3_256", indent, source->sm3_256, SM3_256_DIGEST_SIZE);
	break;
#endif
      default:
	printf("%*s" "TPMU_HA: unknown selector\n", indent, "");
    }
    return;
}

/* Table 76 - Definition of TPMT_HA Structure <IN/OUT> */

void TSS_TPMT_HA_Print(TPMT_HA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->hashAlg, indent+2);	
    TSS_TPMU_HA_Print(&source->digest, source->hashAlg, indent+2);
    return;
}

/* Table 89 - Definition of TPMS_PCR_SELECT Structure */

void TSS_TPMS_PCR_SELECT_Print(TPMS_PCR_SELECT *source, unsigned int indent)
{
    printf("%*s" "TSS_TPMS_PCR_SELECT sizeofSelect %u\n", indent, "", source->sizeofSelect);
    TSS_PrintAlli("pcrSelect", indent, source->pcrSelect, source->sizeofSelect);
    return;
}

/* Table 90 - Definition of TPMS_PCR_SELECTION Structure */

void TSS_TPMS_PCR_SELECTION_Print(TPMS_PCR_SELECTION *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->hash, indent+2);
    TSS_PrintAlli("TPMS_PCR_SELECTION", indent+2,
		  source->pcrSelect,
		  source->sizeofSelect);
    return;
}

/* Table 93 - Definition of TPMT_TK_CREATION Structure */

void TSS_TPMT_TK_CREATION_Print(TPMT_TK_CREATION *source, unsigned int indent)
{
    TSS_TPM_ST_Print(source->tag, indent);
    TSS_TPM_HANDLE_Print(source->hierarchy, indent);	
    TSS_PrintAlli("digest", indent,
		  source->digest.t.buffer,
		  source->digest.t.size);
    return;
}

/* Table 94 - Definition of TPMT_TK_VERIFIED Structure */

void TSS_TPMT_TK_VERIFIED_Print(TPMT_TK_VERIFIED *source, unsigned int indent)
{
    TSS_TPM_ST_Print(source->tag, indent);
    TSS_TPM_HANDLE_Print(source->hierarchy, indent);	
    TSS_PrintAlli("digest", indent,
		  source->digest.t.buffer,
		  source->digest.t.size);
    return;
}
	
/* Table 95 - Definition of TPMT_TK_AUTH Structure */

void TSS_TPMT_TK_AUTH_Print(TPMT_TK_AUTH *source, unsigned int indent)
{
    TSS_TPM_ST_Print(source->tag, indent);
    TSS_TPM_HANDLE_Print(source->hierarchy, indent);	
    TSS_PrintAlli("digest", indent,
		  source->digest.t.buffer,
		  source->digest.t.size);
    return;
}

/* Table 96 - Definition of TPMT_TK_HASHCHECK Structure */

void TSS_TPMT_TK_HASHCHECK_Print(TPMT_TK_AUTH *source, unsigned int indent)
{
    TSS_TPM_ST_Print(source->tag, indent);
    TSS_TPM_HANDLE_Print(source->hierarchy, indent);	
    TSS_PrintAlli("digest", indent,
		  source->digest.t.buffer,
		  source->digest.t.size);
    return;
}

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

void TSS_TPML_PCR_SELECTION_Print(TPML_PCR_SELECTION *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_PCR_SELECTION count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPMS_PCR_SELECTION_Print(&source->pcrSelections[i], indent);
    }
    return;
}

/* Table 115 - Definition of TPMS_CLOCK_INFO Structure */

void TSS_TPMS_CLOCK_INFO_Print(TPMS_CLOCK_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_CLOCK_INFO clock %"PRIu64"\n", indent, "", source->clock);
    printf("%*s" "TPMS_CLOCK_INFO resetCount %u\n", indent, "", source->resetCount);
    printf("%*s" "TPMS_CLOCK_INFO restartCount %u\n", indent, "", source->restartCount);
    printf("%*s" "TPMS_CLOCK_INFO safe %x\n", indent, "", source->safe);
    return;
}

/* Table 116 - Definition of TPMS_TIME_INFO Structure */

void TSS_TPMS_TIME_INFO_Print(TPMS_TIME_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_TIME_INFO time %"PRIu64"\n", indent, "", source->time);
    TSS_TPMS_CLOCK_INFO_Print(&source->clockInfo, indent+2);
    return;
}
    
/* Table 117 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

void TSS_TPMS_TIME_ATTEST_INFO_Print(TPMS_TIME_ATTEST_INFO *source, unsigned int indent)
{
    TSS_TPMS_TIME_INFO_Print(&source->time, indent+2);
    printf("%*s" "TPMS_TIME_ATTEST_INFO firmwareVersion %"PRIu64"\n", indent, "", source->firmwareVersion);
    return;
}

/* Table 118 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

void TSS_TPMS_CERTIFY_INFO_Print(TPMS_CERTIFY_INFO *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_CERTIFY_INFO name", indent,
		  source->name.b.buffer,
		  source->name.b.size);
    TSS_PrintAlli("TPMS_CERTIFY_INFO qualifiedName", indent,
		  source->qualifiedName.b.buffer,
		  source->qualifiedName.b.size);
    return;
}

/* Table 119 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

void TSS_TPMS_QUOTE_INFO_Print(TPMS_QUOTE_INFO *source, unsigned int indent)
{
    TSS_TPML_PCR_SELECTION_Print(&source->pcrSelect, indent+2);
    TSS_PrintAlli("TPMS_QUOTE_INFO pcrDigest", indent+2,
		  source->pcrDigest.b.buffer,
		  source->pcrDigest.b.size);
    return;
}

/* Table 120 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

void TSS_TPMS_COMMAND_AUDIT_INFO_Print(TPMS_COMMAND_AUDIT_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_COMMAND_AUDIT_INFO auditCounter %"PRIu64"\n", indent, "", source->auditCounter);
    TSS_TPM_ALG_ID_Print(source->digestAlg, indent);
    TSS_PrintAlli("TPMS_COMMAND_AUDIT_INFO auditDigest	", indent,
		  source->auditDigest.b.buffer,
		  source->auditDigest.b.size);
    TSS_PrintAlli("TPMS_COMMAND_AUDIT_INFO auditDigest	", indent,
		  source->commandDigest	.b.buffer,
		  source->commandDigest	.b.size);
    return;
}
  
/* Table 121 - Definition of TPMS_SESSION_AUDIT_INFO Structure */

void TSS_TPMS_SESSION_AUDIT_INFO_Print(TPMS_SESSION_AUDIT_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_SESSION_AUDIT_INFO exclusiveSession %d\n", indent, "",
	   source->exclusiveSession);
    TSS_PrintAlli("TPMS_SESSION_AUDIT_INFO sessionDigest", indent,
		  source->sessionDigest.b.buffer,
		  source->sessionDigest.b.size);
    return;
}

/* Table 122 - Definition of TPMS_CREATION_INFO Structure <OUT> */

void TSS_TPMS_CREATION_INFO_Print(TPMS_CREATION_INFO *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_CREATION_INFO objectName", indent,
		  source->objectName.b.buffer,
		  source->objectName.b.size);
    TSS_PrintAlli("TPMS_CREATION_INFO creationHash", indent,
		  source->creationHash.b.buffer,
		  source->creationHash.b.size);
    return;
}

/* Table 123 - Definition of TPMS_NV_CERTIFY_INFO Structure */

void TSS_TPMS_NV_CERTIFY_INFO_Print(TPMS_NV_CERTIFY_INFO  *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_NV_CERTIFY_INFO indexName", indent,
		  source->indexName.b.buffer,
		  source->indexName.b.size);
    printf("%*s" "TPMS_NV_CERTIFY_INFO offset %d\n", indent, "",  source->offset);
    TSS_PrintAlli("TPMS_NV_CERTIFY_INFO nvContents", indent,
		  source->nvContents.b.buffer,
		  source->nvContents.b.size);
    return;
}

/* Table 124 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

void TSS_TPMI_ST_ATTEST_Print(TPMI_ST_ATTEST selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_CERTIFY\n", indent, "");
	break;
      case TPM_ST_ATTEST_CREATION:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_CREATION\n", indent, "");
	break;
      case TPM_ST_ATTEST_QUOTE:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_QUOTE\n", indent, "");
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_COMMAND_AUDIT\n", indent, "");
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_SESSION_AUDIT\n", indent, "");
	break;
      case TPM_ST_ATTEST_TIME:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_TIME\n", indent, "");
	break;
      case TPM_ST_ATTEST_NV:
	printf("%*s" "TPMI_ST_ATTEST TPM_ST_ATTEST_NV\n", indent, "");
	break;
      default:
	printf("%*s" "TPMI_ST_ATTEST_Print: selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 125 - Definition of TPMU_ATTEST Union <OUT> */

void TSS_TPMU_ATTEST_Print(TPMU_ATTEST *source, TPMI_ST_ATTEST selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	TSS_TPMS_CERTIFY_INFO_Print(&source->certify, indent+2);
	break;
      case TPM_ST_ATTEST_CREATION:
	TSS_TPMS_CREATION_INFO_Print(&source->creation, indent+2);
	break;
      case TPM_ST_ATTEST_QUOTE:
	TSS_TPMS_QUOTE_INFO_Print(&source->quote, indent+2);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	TSS_TPMS_COMMAND_AUDIT_INFO_Print(&source->commandAudit, indent+2);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	TSS_TPMS_SESSION_AUDIT_INFO_Print(&source->sessionAudit, indent+2);
	break;
      case TPM_ST_ATTEST_TIME:
	TSS_TPMS_TIME_ATTEST_INFO_Print(&source->time, indent+2);
	break;
      case TPM_ST_ATTEST_NV:
	TSS_TPMS_NV_CERTIFY_INFO_Print(&source->nv, indent+2);
	break;
      default:
	printf("%*s" "TPMU_ATTEST selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 126 - Definition of TPMS_ATTEST Structure <OUT> */

void TSS_TPMS_ATTEST_Print(TPMS_ATTEST *source, unsigned int indent)
{
    printf("%*s" "TPMS_ATTEST magic %08x\n", indent+2, "", source->magic);
    TSS_TPMI_ST_ATTEST_Print(source->type, indent+2);
    TSS_PrintAlli("TPMS_ATTEST extraData", indent+2,
		  source->extraData.b.buffer,
		  source->extraData.b.size);
    TSS_TPMS_CLOCK_INFO_Print(&source->clockInfo, indent+2);
    TSS_TPMU_ATTEST_Print(&source->attested, source->type, indent+2);
    return;
}

/* Table 127 - Definition of TPM2B_ATTEST Structure <OUT> */

void TSS_TPM2B_ATTEST_Print(TPM2B_ATTEST *source, unsigned int indent)
{
    TPM_RC			rc = 0;
    TPMS_ATTEST 		attests;
    uint32_t			size;
    uint8_t			*buffer = NULL;

    /* unmarshal the TPMS_ATTEST from the TPM2B_ATTEST */
    if (rc == 0) {
	buffer = source->t.attestationData;
	size = source->t.size;
	rc = TPMS_ATTEST_Unmarshal(&attests, &buffer, &size);
    }
    if (rc == 0) {
	TSS_TPMS_ATTEST_Print(&attests, indent+2);
    }
    else {
	printf("%*s" "TPMS_ATTEST_Unmarshal failed\n", indent, "");
    }
    return;
}

/* Table 128 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

void TSS_TPMS_AUTH_COMMAND_Print(TPMS_AUTH_COMMAND *source, unsigned int indent)
{
    TSS_TPM_HANDLE_Print(source->sessionHandle, indent);	
    TSS_PrintAlli("TPMS_AUTH_COMMANDnonce", indent,
		  source->nonce.t.buffer,
		  source->nonce.t.size);
    TSS_TPMA_SESSION_Print(source->sessionAttributes, indent);
    TSS_PrintAlli("TPMS_AUTH_COMMANDhmac", indent,
		  source->hmac.t.buffer,
		  source->hmac.t.size);
    return;
}

/* Table 129 - Definition of TPMS_AUTH_RESPONSE Structure <OUT> */

void TSS_TPMS_AUTH_RESPONSE_Print(TPMS_AUTH_RESPONSE *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_AUTH_RESPONSE nonce", indent,
		  source->nonce.t.buffer,
		  source->nonce.t.size);
    TSS_TPMA_SESSION_Print(source->sessionAttributes, indent);
    TSS_PrintAlli("TPMS_AUTH_RESPONSE hmac", indent,
		  source->hmac.t.buffer,
		  source->hmac.t.size);
    return;
}
	
/* Table 135 - Definition of TPMT_SYM_DEF_OBJECT Structure */

void TSS_TPMT_SYM_DEF_OBJECT_Print(TPMT_SYM_DEF_OBJECT *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->algorithm, indent+2);
    printf("%*s" "TPMU_SYM_KEY_BITS: %u\n", indent+2, "", source->keyBits.sym);
    TSS_TPM_ALG_ID_Print(source->mode.sym, indent+2);
    return;
}

/* Table 139 - Definition of TPMS_DERIVE Structure */

void TSS_TPMS_DERIVE_Print(TPMS_DERIVE *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_DERIVE label", indent,
		  source->label.t.buffer,
		  source->label.t.size);
    TSS_PrintAlli("TPMS_DERIVE context", indent,    
		  source->context.t.buffer,
		  source->context.t.size);
    return;
}

/* Table 143 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

void TSS_TPMS_SENSITIVE_CREATE_Print(TPMS_SENSITIVE_CREATE *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_SENSITIVE_CREATE userAuth", indent,    
		  source->userAuth.t.buffer,
		  source->userAuth.t.size);
    
    TSS_PrintAlli("TPMS_SENSITIVE_CREATE data", indent,    
		  source->data.t.buffer,
		  source->data.t.size);
    return;
}

/* Table 144 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

void TSS_TPM2B_SENSITIVE_CREATE_Print(TPM2B_SENSITIVE_CREATE *source, unsigned int indent)
{
    printf("%*s" "TPM2B_SENSITIVE_CREATE size %u\n", indent+2, "", source->size);
    TSS_TPMS_SENSITIVE_CREATE_Print(&source->sensitive, indent+2);
    return;
}

/* Table 146 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

void TSS_TPMS_SCHEME_ECDAA_Print(TPMS_SCHEME_ECDAA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->hashAlg, indent+2);
    printf("%*s" "TPMS_SCHEME_ECDAA count %u\n", indent+2, "", source->count);
    return;
}

/* Table 149 - Definition of TPMS_SCHEME_XOR Structure */

void TSS_TPMS_SCHEME_XOR_Print(TPMS_SCHEME_XOR *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->hashAlg, indent+2);
    TSS_TPM_ALG_ID_Print(source->kdf, indent+2);
    return;
}

/* Table 150 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

void TSS_TPMU_SCHEME_KEYEDHASH_Print(TPMU_SCHEME_KEYEDHASH *source, TPMI_ALG_KEYEDHASH_SCHEME selector,
				     unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TSS_TPM_ALG_ID_Print(source->hmac.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	TSS_TPMS_SCHEME_XOR_Print(&source->xorr, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_SCHEME_KEYEDHASH selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 151 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

void TSS_TPMT_KEYEDHASH_SCHEME_Print(TPMT_KEYEDHASH_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_SCHEME_KEYEDHASH_Print(&source->details, source->scheme, indent+2);
    }
    return;
}

/* Table 154 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

void TSS_TPMU_SIG_SCHEME_Print(TPMU_SIG_SCHEME *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TSS_TPM_ALG_ID_Print(source->rsassa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TSS_TPM_ALG_ID_Print(source->rsapss.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TSS_TPM_ALG_ID_Print(source->ecdsa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TSS_TPMS_SCHEME_ECDAA_Print(&source->ecdaa, indent+2);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TSS_TPM_ALG_ID_Print(source->sm2.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TSS_TPM_ALG_ID_Print(source->ecSchnorr.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TSS_TPM_ALG_ID_Print(source->hmac.hashAlg, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_SIG_SCHEME selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 155 - Definition of TPMT_SIG_SCHEME Structure */

void TSS_TPMT_SIG_SCHEME_Print(TPMT_SIG_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_SIG_SCHEME_Print(&source->details, source->scheme, indent+2);
    }
    return;
}

/* Table 160 - Definition of TPMT_KDF_SCHEME Structure */

void TSS_TPMT_KDF_SCHEME_Print(TPMT_KDF_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print(source->details.mgf1.hashAlg, indent+2);
    }
    return;
}

/* Table 162 - Definition of TPMU_ASYM_SCHEME Union */

void TSS_TPMU_ASYM_SCHEME_Print(TPMU_ASYM_SCHEME *source, TPMI_ALG_ASYM_SCHEME selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	TSS_TPM_ALG_ID_Print(source->ecdh.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	TSS_TPM_ALG_ID_Print(source->ecmqvh.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TSS_TPM_ALG_ID_Print(source->rsassa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TSS_TPM_ALG_ID_Print(source->rsapss.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TSS_TPM_ALG_ID_Print(source->ecdsa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TSS_TPMS_SCHEME_ECDAA_Print(&source->ecdaa, indent+2);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TSS_TPM_ALG_ID_Print(source->sm2.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TSS_TPM_ALG_ID_Print(source->ecSchnorr.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	TSS_TPM_ALG_ID_Print(source->oaep.hashAlg, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_ASYM_SCHEME selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 163 - Definition of TPMT_ASYM_SCHEME Structure <> */

void TSS_TPMT_ASYM_SCHEME_Print(TPMT_ASYM_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_ASYM_SCHEME_Print(&source->details, source->scheme, indent+2);
    }
    return;
}
	
/* Table 165 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

void TSS_TPMT_RSA_SCHEME_Print(TPMT_RSA_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print(source->details.anySig.hashAlg, indent+2);
    }
    return;
}

/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

void TSS_TPMI_RSA_KEY_BITS_Print(TPMI_RSA_KEY_BITS source, unsigned int indent)
{
    printf("%*s" "TPM_KEY_BITS: %u\n", indent, "", source);
    return;
}

/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

void TSS_TPMI_ECC_CURVE_Print(TPMI_ECC_CURVE source, unsigned int indent)
{
    switch (source) {
#ifdef TPM_ECC_BN_P256
      case TPM_ECC_BN_P256:
	printf("%*s" "TPMI_ECC_CURVE TPM_ECC_BN_P256\n", indent, "");
	break;
#endif
#ifdef TPM_ECC_NIST_P256
      case TPM_ECC_NIST_P256:
	printf("%*s" "TPMI_ECC_CURVE TPM_ECC_NIST_P256\n", indent, "");
	break;
#endif
#ifdef TPM_ECC_NIST_P384
      case TPM_ECC_NIST_P384:
	printf("%*s" "TPMI_ECC_CURVE TPM_ECC_NIST_P384\n", indent, "");
	break;
#endif
      default:
	printf("%*s" "TPMI_ECC_CURVE %04hx unknown\n", indent, "", source);
    }
    return;
}

/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

void TSS_TPMT_ECC_SCHEME_Print(TPMT_ECC_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print(source->details.anySig.hashAlg, indent+2);
    }
    return;
}

/* Table 168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

void TSS_TPMS_SIGNATURE_RSA_Print(TPMS_SIGNATURE_RSA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->hash, indent+2);
    TSS_PrintAlli("TPMS_SIGNATURE_RSA", indent+2,
		  source->sig.t.buffer,
		  source->sig.t.size);
    return;
}

/* Table 169 - Definition of Types for {RSA} Signature */

void TSS_TPMS_SIGNATURE_RSASSA_Print(TPMS_SIGNATURE_RSASSA *source, unsigned int indent)
{
    TSS_TPMS_SIGNATURE_RSA_Print(source, indent+2);
    return;
}

/* Table 172 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

void TSS_TPMU_SIGNATURE_Print(TPMU_SIGNATURE *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ALG_RSASSA:
	TSS_TPMS_SIGNATURE_RSASSA_Print(&source->rsassa, indent+2);
	break;
#if 0
      case TPM_ALG_RSAPSS:
	TSS_TPMS_SIGNATURE_RSAPSS_Print(&source->rsapss, indent+2);
	break;
      case TPM_ALG_ECDSA:
	TSS_TPMS_SIGNATURE_ECDSA_Print(&source->ecdsa, indent+2);
	break;
      case TPM_ALG_ECDAA:
	TSS_TPMS_SIGNATURE_ECDSA_Print(&source->ecdaa, indent+2);
	break;
      case TPM_ALG_SM2:
	TSS_TPMS_SIGNATURE_ECDSA_Print(&source->sm2, indent+2);
	break;
      case TPM_ALG_ECSCHNORR:
	TSS_TPMS_SIGNATURE_ECDSA_Print(&source->ecschnorr, indent+2);
	break;
      case TPM_ALG_HMAC:
	TSS_TPMT_HA_Print(&source->hmac, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_SIGNATURE selection %04hx not implemented\n", indent, "", selector);
	
    }
}

/* Table 173 - Definition of TPMT_SIGNATURE Structure */

void TSS_TPMT_SIGNATURE_Print(TPMT_SIGNATURE *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print(source->sigAlg, indent+2);
    if (source->sigAlg != TPM_ALG_NULL) {
	TSS_TPMU_SIGNATURE_Print(&source->signature, source->sigAlg, indent+2);
    }
    return;
}

/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

void TSS_TPMI_ALG_PUBLIC_Print(TPMI_ALG_PUBLIC source, unsigned int indent)
{
    switch (source) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	printf("%*s" "TPMI_ALG_PUBLIC: TPM_ALG_KEYEDHASH\n", indent, "");
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	printf("%*s" "TPMI_ALG_PUBLIC: TPM_ALG_RSA\n", indent, "");
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	printf("%*s" "TPMI_ALG_PUBLIC: TPM_ALG_ECC\n", indent, "");
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	printf("%*s" "TPMI_ALG_PUBLIC: TPM_ALG_SYMCIPHER\n", indent, "");
	break;
#endif
      default:
	printf("%*s" "TPMI_ALG_PUBLIC: selection %04hx not implemented\n", indent, "", source);
    }
    return;
}
    
/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

void TSS_TPMU_PUBLIC_ID_Print(TPMU_PUBLIC_ID *source, TPMI_ALG_PUBLIC selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	TSS_PrintAlli("TPM_ALG_KEYEDHASH", indent,
		      source->keyedHash.b.buffer,
		      source->keyedHash.b.size);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TSS_PrintAlli("TPM_ALG_SYMCIPHER", indent,
		      source->sym.b.buffer,
		      source->sym.b.size);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA: 
	TSS_PrintAlli("TPM_ALG_RSA", indent,
		      source->rsa.b.buffer,
		      source->rsa.b.size);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TSS_PrintAlli("TPM_ALG_ECC x", indent,
		      source->ecc.x.b.buffer,
		      source->ecc.x.b.size);
	TSS_PrintAlli("TPM_ALG_ECC y", indent,
		      source->ecc.y.b.buffer,
		      source->ecc.y.b.size);
	break;
#endif
      default:
	printf("%*s" "TPMU_PUBLIC_ID_Print: selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */

void TSS_TPMS_RSA_PARMS_Print(TPMS_RSA_PARMS *source, unsigned int indent)
{
    TSS_TPMT_SYM_DEF_OBJECT_Print(&source->symmetric, indent+2);
    TSS_TPMT_RSA_SCHEME_Print(&source->scheme, indent+2);
    TSS_TPMI_RSA_KEY_BITS_Print(source->keyBits, indent+2);
    printf("%*s" "TPMS_RSA_PARMS exponent %08x\n", indent+2, "", source->exponent);
    return;
}

/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure */

void TSS_TPMS_ECC_PARMS_Print(TPMS_ECC_PARMS *source, unsigned int indent)
{
    TSS_TPMT_SYM_DEF_OBJECT_Print(&source->symmetric, indent+2);
    TSS_TPMT_ECC_SCHEME_Print(&source->scheme, indent+2);
    TSS_TPMI_ECC_CURVE_Print(source->curveID, indent+2);
    TSS_TPMT_KDF_SCHEME_Print(&source->kdf, indent+2);
    return;
}

void TSS_TPMS_KEYEDHASH_PARMS_Print(TPMS_KEYEDHASH_PARMS *source, unsigned int indent)
{
    TSS_TPMT_KEYEDHASH_SCHEME_Print(&source->scheme, indent+2);
    return;
}


/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

void TSS_TPMU_PUBLIC_PARMS_Print(TPMU_PUBLIC_PARMS *source, uint32_t selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ALG_KEYEDHASH:
	TSS_TPMS_KEYEDHASH_PARMS_Print(&source->keyedHashDetail, indent+2);
	break;
#if 0
      case TPM_ALG_SYMCIPHER:
	TSS_TPMS_SYMCIPHER_PARMS_Print(&source->symDetail, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	TSS_TPMS_RSA_PARMS_Print(&source->rsaDetail, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TSS_TPMS_ECC_PARMS_Print(&source->eccDetail, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_PUBLIC_PARMS : selector %04x not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 184 - Definition of TPMT_PUBLIC Structure */

void TSS_TPMT_PUBLIC_Print(TPMT_PUBLIC *source, unsigned int indent)
{
    TSS_TPMI_ALG_PUBLIC_Print(source->type, indent+2);
    TSS_TPM_ALG_ID_Print(source->nameAlg, indent+2);
    TSS_TPMA_OBJECT_Print(source->objectAttributes, indent+2);	
    TSS_PrintAlli("authPolicy: ", indent+2,
		  source->authPolicy.b.buffer, source->authPolicy.b.size);
    TSS_TPMU_PUBLIC_PARMS_Print(&source->parameters, source->type, indent+2);		
    TSS_TPMU_PUBLIC_ID_Print(&source->unique, source->type, indent+2);			
    return;
}

/* Table 205 - Definition of (UINT32) TPMA_NV Bits */

void TSS_TPMA_NV_Print(TPMA_NV source, unsigned int indent)
{
    uint32_t nvType;

    if (source.val & TPMA_NVA_PPWRITE) printf("%*s" "TPMA_NV_PPWRITE\n", indent, "");
    if (source.val & TPMA_NVA_OWNERWRITE) printf("%*s" "TPMA_NV_OWNERWRITE\n", indent, "");
    if (source.val & TPMA_NVA_AUTHWRITE) printf("%*s" "TPMA_NV_AUTHWRITE\n", indent, "");
    if (source.val & TPMA_NVA_POLICYWRITE) printf("%*s" "TPMA_NV_POLICYWRITE\n", indent, "");

    nvType = (source.val & TPMA_NVA_TPM_NT_MASK) >> 4;
    switch (nvType) {
      case TPM_NT_ORDINARY:
	printf("%*s" "TPM_NT_ORDINARY\n", indent, "");
	break;
      case TPM_NT_COUNTER:
	printf("%*s" "TPM_NT_COUNTER\n", indent, "");
	break;
      case TPM_NT_BITS:
	printf("%*s" "TPM_NT_COUNTER\n", indent, "");
	break;
      case TPM_NT_EXTEND:
	printf("%*s" "TPM_NT_EXTEND\n", indent, "");
	break;
      case TPM_NT_PIN_FAIL:
	printf("%*s" "TPM_NT_PIN_FAIL\n", indent, "");
	break;
      case TPM_NT_PIN_PASS:
	printf("%*s" "TPM_NT_PIN_PASS\n", indent, "");
	break;
      default:
	printf("%*s %02x" "type unknown\n", indent, "", nvType);
    }

    if (source.val & TPMA_NVA_POLICY_DELETE) printf("%*s" "TPMA_NV_POLICY_DELETE\n", indent, "");
    if (source.val & TPMA_NVA_WRITELOCKED) printf("%*s" "TPMA_NV_WRITELOCKED\n", indent, "");
    if (source.val & TPMA_NVA_WRITEALL) printf("%*s" "TPMA_NV_WRITEALL\n", indent, "");
    if (source.val & TPMA_NVA_WRITEDEFINE) printf("%*s" "TPMA_NV_WRITEDEFINE\n", indent, "");
    if (source.val & TPMA_NVA_WRITE_STCLEAR) printf("%*s" "TPMA_NV_WRITE_STCLEAR\n", indent, "");
    if (source.val & TPMA_NVA_GLOBALLOCK) printf("%*s" "TPMA_NV_GLOBALLOCK\n", indent, "");
    if (source.val & TPMA_NVA_PPREAD) printf("%*s" "TPMA_NV_PPREAD\n", indent, "");
    if (source.val & TPMA_NVA_OWNERREAD) printf("%*s" "TPMA_NV_OWNERREAD\n", indent, "");
    if (source.val & TPMA_NVA_AUTHREAD) printf("%*s" "TPMA_NV_AUTHREAD\n", indent, "");
    if (source.val & TPMA_NVA_POLICYREAD) printf("%*s" "TPMA_NV_POLICYREAD\n", indent, "");
    if (source.val & TPMA_NVA_NO_DA) printf("%*s" "TPMA_NV_NO_DA\n", indent, "");
    if (source.val & TPMA_NVA_ORDERLY) printf("%*s" "TPMA_NV_ORDERLY\n", indent, "");
    if (source.val & TPMA_NVA_CLEAR_STCLEAR) printf("%*s" "TPMA_NV_CLEAR_STCLEAR\n", indent, "");
    if (source.val & TPMA_NVA_READLOCKED) printf("%*s" "TPMA_NV_READLOCKED\n", indent, "");
    if (source.val & TPMA_NVA_WRITTEN) printf("%*s" "TPMA_NV_WRITTEN\n", indent, "");
    if (source.val & TPMA_NVA_PLATFORMCREATE) printf("%*s" "TPMA_NV_PLATFORMCREATE\n", indent, "");
    if (source.val & TPMA_NVA_READ_STCLEAR) printf("%*s" "TPMA_NV_READ_STCLEAR\n", indent, "");
    return;
}
