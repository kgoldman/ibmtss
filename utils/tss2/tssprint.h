/********************************************************************************/
/*										*/
/*			     Structure Print Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssprint.h 1147 2018-02-08 23:28:29Z kgoldman $		*/
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

/* This is a semi-public header. The API is not guaranteed to be stable, and the format of the
   output is subject to change

   It is useful for application debug.
*/

#ifndef TSSPRINT_H
#define TSSPRINT_H

#include <stdint.h>
#include <stdio.h>

#ifndef TPM_TSS
#define TPM_TSS
#endif
#include <tss2/TPM_Types.h>

#define LOGLEVEL_INFO 6		/* LOGLEVEL_INFO prints a concise output */
#define LOGLEVEL_DEBUG 7	/* LOGLEVEL_DEBUG prints a verbose output */

#ifdef __cplusplus
extern "C" {
#endif

    #ifdef TPM_NO_PRINT

    /* return code to eliminate "statement has no effect" compiler warning */
    extern int tssSwallowRc;
    /* function prototype to match the printf prototype */
    int TSS_SwallowPrintf(const char *format, ...);
    /* macro to compile out printf */
#define printf tssSwallowRc = 0 && TSS_SwallowPrintf

    #endif
    
    LIB_EXPORT 
    uint32_t TSS_Array_Scan(unsigned char **data, size_t *len, const char *string);
    LIB_EXPORT 
    void TSS_PrintAll(const char *string, const unsigned char* buff, uint32_t length);
    LIB_EXPORT 
    void TSS_PrintAlli(const char *string, unsigned int indent,
		       const unsigned char* buff, uint32_t length);
    LIB_EXPORT
    void TSS_PrintAllLogLevel(uint32_t log_level, const char *string, unsigned int indent,
			      const unsigned char* buff, uint32_t length);
    LIB_EXPORT
    void TSS_TPM_ALG_ID_Print(TPM_ALG_ID source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_ECC_CURVE_Print(TPM_ECC_CURVE source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_CC_Print(TPM_CC source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_TPMA_ALGORITHM_Print(TPMA_ALGORITHM source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_CLOCK_ADJUST_Print(TPM_CLOCK_ADJUST source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_EO_Print(TPM_EO source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_ST_Print(TPM_ST source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_SU_Print(TPM_SU source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_SE_Print(TPM_SE source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_CAP_Print(TPM_CAP source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_HANDLE_Print(TPM_HANDLE source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM_TPMA_ALGORITHM_Print(TPMA_ALGORITHM source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_OBJECT_Print(TPMA_OBJECT source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_LOCALITY_Print(TPMA_LOCALITY source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_SESSION_Print(TPMA_SESSION source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_PERMANENT_Print(TPMA_PERMANENT source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_STARTUP_CLEAR_Print(TPMA_STARTUP_CLEAR source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_MEMORY_Print(TPMA_MEMORY source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_HA_Print(TPMU_HA *source, uint32_t selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_HA_Print(TPMT_HA *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_PCR_SELECT_Print(TPMS_PCR_SELECT *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_PCR_SELECTION_Print(TPMS_PCR_SELECTION *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPML_PCR_SELECTION_Print(TPML_PCR_SELECTION *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_TK_CREATION_Print(TPMT_TK_CREATION *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_TK_VERIFIED_Print(TPMT_TK_VERIFIED *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_TK_AUTH_Print(TPMT_TK_AUTH *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_TK_HASHCHECK_Print(TPMT_TK_AUTH *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_CLOCK_INFO_Print(TPMS_CLOCK_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_TIME_INFO_Print(TPMS_TIME_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_TIME_ATTEST_INFO_Print(TPMS_TIME_ATTEST_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_CERTIFY_INFO_Print(TPMS_CERTIFY_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_QUOTE_INFO_Print(TPMS_QUOTE_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_COMMAND_AUDIT_INFO_Print(TPMS_COMMAND_AUDIT_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_SESSION_AUDIT_INFO_Print(TPMS_SESSION_AUDIT_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_CREATION_INFO_Print(TPMS_CREATION_INFO *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_NV_CERTIFY_INFO_Print(TPMS_NV_CERTIFY_INFO  *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMI_ST_ATTEST_Print(TPMI_ST_ATTEST selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_ATTEST_Print(TPMU_ATTEST *source, TPMI_ST_ATTEST selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_ATTEST_Print(TPMS_ATTEST *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM2B_ATTEST_Print(TPM2B_ATTEST *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_AUTH_COMMAND_Print(TPMS_AUTH_COMMAND *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_AUTH_RESPONSE_Print(TPMS_AUTH_RESPONSE *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_SYM_DEF_OBJECT_Print(TPMT_SYM_DEF_OBJECT *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_DERIVE_Print(TPMS_DERIVE *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_SENSITIVE_CREATE_Print(TPMS_SENSITIVE_CREATE *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPM2B_SENSITIVE_CREATE_Print(TPM2B_SENSITIVE_CREATE *source, unsigned int indent);    
    LIB_EXPORT
    void TSS_TPMS_SCHEME_ECDAA_Print(TPMS_SCHEME_ECDAA *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_SCHEME_XOR_Print(TPMS_SCHEME_XOR *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_SCHEME_KEYEDHASH_Print(TPMU_SCHEME_KEYEDHASH *source, TPMI_ALG_KEYEDHASH_SCHEME selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_KEYEDHASH_SCHEME_Print(TPMT_KEYEDHASH_SCHEME  *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_SIG_SCHEME_Print(TPMU_SIG_SCHEME *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_SIG_SCHEME_Print(TPMT_SIG_SCHEME *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_KDF_SCHEME_Print(TPMT_KDF_SCHEME *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_ASYM_SCHEME_Print(TPMU_ASYM_SCHEME *source, TPMI_ALG_ASYM_SCHEME selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_ASYM_SCHEME_Print(TPMT_ASYM_SCHEME *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_RSA_SCHEME_Print(TPMT_RSA_SCHEME *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMI_RSA_KEY_BITS_Print(TPMI_RSA_KEY_BITS source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMI_ECC_CURVE_Print(TPMI_ECC_CURVE source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_ECC_SCHEME_Print(TPMT_ECC_SCHEME *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_SIGNATURE_RSA_Print(TPMS_SIGNATURE_RSA *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_SIGNATURE_RSASSA_Print(TPMS_SIGNATURE_RSASSA *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_SIGNATURE_Print(TPMU_SIGNATURE *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_SIGNATURE_Print(TPMT_SIGNATURE *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_PUBLIC_ID_Print(TPMU_PUBLIC_ID *source, TPMI_ALG_PUBLIC selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMI_ALG_PUBLIC_Print(TPMI_ALG_PUBLIC source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_ECC_PARMS_Print(TPMS_ECC_PARMS *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_RSA_PARMS_Print(TPMS_RSA_PARMS *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMS_KEYEDHASH_PARMS_Print(TPMS_KEYEDHASH_PARMS *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMU_PUBLIC_PARMS_Print(TPMU_PUBLIC_PARMS *source, UINT32 selector, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMT_PUBLIC_Print(TPMT_PUBLIC *source, unsigned int indent);
    LIB_EXPORT
    void TSS_TPMA_NV_Print(TPMA_NV source, unsigned int indent);

#ifdef __cplusplus
}
#endif

#endif
