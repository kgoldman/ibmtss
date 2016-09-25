/********************************************************************************/
/*										*/
/*			    TSS Primary API 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tss.c 749 2016-09-20 17:10:53Z kgoldman $			*/
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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include "tssauth.h"
#include <tss2/tss.h>
#include <tss2/tssproperties.h>
#include <tss2/tsstransmit.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/CpriHash_fp.h>
#include <tssccattributes.h>
#include <tss2/tsscrypto.h>
#include <tss2/tssprint.h>

/* Files:

   h01xxxxxx.bin - NV index name
   h02xxxxxx.bin - hmac session context
   h03xxxxxx.bin - policy session context
   h80xxxxxx.bin - transient object name

   cxxxx...xxxx.bin - context blob name
*/

/* NOTE Synchronize with

   TSS_HmacSession_InitContext
   TSS_HmacSession_Unmarshal
   TSS_HmacSession_Marshal
*/

struct TSS_HMAC_CONTEXT {
    TPMI_SH_AUTH_SESSION	sessionHandle;		/* the session handle */
    TPMI_ALG_HASH		authHashAlg;		/* hash algorithm to use for the session */
    uint32_t           		sizeInBytes;		/* hash algorithm mapped to size */
    TPMT_SYM_DEF 		symmetric;		/* the algorithm and key size for parameter
							   encryption */
    TPMI_DH_ENTITY 		bind;			/* bind handle */
    TPM2B_NAME			bindName;		/* Name corresponding to the the bind
							   handle */
    TPM2B_AUTH			bindAuthValue;		/* password corresponding to the bind
							   handle */
    TPM2B_NONCE 		nonceTPM;		/* from TPM in response */
    TPM2B_NONCE			nonceCaller;		/* from caller in command */
    TPM2B_DIGEST		sessionKey;		/* from KDFa at session creation */
    TPM_SE			sessionType;		/* HMAC, policy, or trial policy */
    uint8_t			isPasswordNeeded;	/* flag set by policy password */
    uint8_t			isAuthValueNeeded;	/* flag set by policy password */
    /* Items below this line are for the lifetime of one command.  they are not saved and loaded. */
    TPM2B_KEY			hmacKey;		/* HMAC key calculated for each command */
    TPM2B_KEY			sessionValue;		/* KDFa secret for parameter encryption */
} TSS_HMAC_CONTEXT;

/* functions for command pre- and post- processing */

typedef TPM_RC (*TSS_PreProcessFunction_t)(TSS_CONTEXT *tssContext,
					   COMMAND_PARAMETERS *in,
					   EXTRA_PARAMETERS *extra);
typedef TPM_RC (*TSS_ChangeAuthFunction_t)(TSS_CONTEXT *tssContext,
					   struct TSS_HMAC_CONTEXT *session,
					   size_t handleNumber,
					   COMMAND_PARAMETERS *in);
typedef TPM_RC (*TSS_PostProcessFunction_t)(TSS_CONTEXT *tssContext,
					    COMMAND_PARAMETERS *in,
					    RESPONSE_PARAMETERS *out,
					    EXTRA_PARAMETERS *extra);

static TPM_RC TSS_PR_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Extra *extra);
static TPM_RC TSS_PR_PolicySigned(TSS_CONTEXT *tssContext,
				  PolicySigned_In *in,
				  PolicySigned_Extra *extra);
static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra);

static TPM_RC TSS_CA_HierarchyChangeAuth(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 HierarchyChangeAuth_In *in);
static TPM_RC TSS_CA_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     struct TSS_HMAC_CONTEXT *session,
					     size_t handleNumber,
					     NV_UndefineSpaceSpecial_In *in);
static TPM_RC TSS_CA_NV_ChangeAuth(TSS_CONTEXT *tssContext,
				   struct TSS_HMAC_CONTEXT *session,
				   size_t handleNumber,
				   NV_ChangeAuth_In *in);


static TPM_RC TSS_PO_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Out *out,
				      StartAuthSession_Extra *extra);
static TPM_RC TSS_PO_ContextSave(TSS_CONTEXT *tssContext,
				 ContextSave_In *in,
				 ContextSave_Out *out,
				 void *extra);
static TPM_RC TSS_PO_ContextLoad(TSS_CONTEXT *tssContext,
				 ContextLoad_In *in,
				 ContextLoad_Out *out,
				 void *extra);
static TPM_RC TSS_PO_FlushContext(TSS_CONTEXT *tssContext,
				  FlushContext_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_EvictControl(TSS_CONTEXT *tssContext,
				  EvictControl_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_Load(TSS_CONTEXT *tssContext,
			  Load_In *in,
			  Load_Out *out,
			  void *extra);
static TPM_RC TSS_PO_LoadExternal(TSS_CONTEXT *tssContext,
				  LoadExternal_In *in,
				  LoadExternal_Out *out,
				  void *extra);
static TPM_RC TSS_PO_HMAC_Start(TSS_CONTEXT *tssContext,
				HMAC_Start_In *in,
				HMAC_Start_Out *out,
				void *extra);
static TPM_RC TSS_PO_HashSequenceStart(TSS_CONTEXT *tssContext,
				       HashSequenceStart_In *in,
				       HashSequenceStart_Out *out,
				       void *extra);
static TPM_RC TSS_PO_SequenceComplete(TSS_CONTEXT *tssContext,
				      SequenceComplete_In *in,
				      SequenceComplete_Out *out,
				      void *extra);
static TPM_RC TSS_PO_EventSequenceComplete(TSS_CONTEXT *tssContext,
					   EventSequenceComplete_In *in,
					   EventSequenceComplete_Out *out,
					   void *extra);
static TPM_RC TSS_PO_PolicyAuthValue(TSS_CONTEXT *tssContext,
				     PolicyAuthValue_In *in,
				     void *out,
				     void *extra);
static TPM_RC TSS_PO_PolicyPassword(TSS_CONTEXT *tssContext,
				    PolicyPassword_In *in,
				    void *out,
				    void *extra);
static TPM_RC TSS_PO_CreatePrimary(TSS_CONTEXT *tssContext,
				   CreatePrimary_In *in,
				   CreatePrimary_Out *out,
				   void *extra);
static TPM_RC TSS_PO_NV_ReadPublic(TSS_CONTEXT *tssContext,
				   NV_ReadPublic_In *in,
				   NV_ReadPublic_Out *out,
				   void *extra);
static TPM_RC TSS_PO_NV_UndefineSpace(TSS_CONTEXT *tssContext,
				      NV_UndefineSpace_In *in,
				      void *out,
				      void *extra);
static TPM_RC TSS_PO_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     NV_UndefineSpaceSpecial_In *in,
					     void *out,
					     void *extra);
static TPM_RC TSS_PO_NV_Write(TSS_CONTEXT *tssContext,
			      NV_Write_In *in,
			      void *out,
			      void *extra);
static TPM_RC TSS_PO_NV_WriteLock(TSS_CONTEXT *tssContext,
				  NV_WriteLock_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_NV_ReadLock(TSS_CONTEXT *tssContext,
				 NV_ReadLock_In *in,
				 void *out,
				 void *extra);

typedef struct TSS_TABLE {
    TPM_CC 			commandCode;
    TSS_PreProcessFunction_t	preProcessFunction;
    TSS_ChangeAuthFunction_t	changeAuthFunction;
    TSS_PostProcessFunction_t 	postProcessFunction;
} TSS_TABLE;

static const TSS_TABLE tssTable [] = {
				 
    {TPM_CC_Startup, NULL, NULL, NULL},
    {TPM_CC_Shutdown, NULL, NULL, NULL},
    {TPM_CC_SelfTest, NULL, NULL, NULL},
    {TPM_CC_IncrementalSelfTest, NULL, NULL, NULL},
    {TPM_CC_GetTestResult, NULL, NULL, NULL},
    {TPM_CC_StartAuthSession, (TSS_PreProcessFunction_t)TSS_PR_StartAuthSession, NULL, (TSS_PostProcessFunction_t)TSS_PO_StartAuthSession},
    {TPM_CC_PolicyRestart, NULL, NULL, NULL},
    {TPM_CC_Create, NULL, NULL, NULL},
    {TPM_CC_Load, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_Load},
    {TPM_CC_LoadExternal, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_LoadExternal},
    {TPM_CC_ReadPublic, NULL, NULL, NULL},
    {TPM_CC_ActivateCredential, NULL, NULL, NULL},
    {TPM_CC_MakeCredential, NULL, NULL, NULL},
    {TPM_CC_Unseal, NULL, NULL, NULL},
    {TPM_CC_ObjectChangeAuth, NULL, NULL, NULL},
    {TPM_CC_Duplicate, NULL, NULL, NULL},
    {TPM_CC_Rewrap, NULL, NULL, NULL},
    {TPM_CC_Import, NULL, NULL, NULL},
    {TPM_CC_RSA_Encrypt, NULL, NULL, NULL},
    {TPM_CC_RSA_Decrypt, NULL, NULL, NULL},
    {TPM_CC_ECDH_KeyGen, NULL, NULL, NULL},
    {TPM_CC_ECDH_ZGen, NULL, NULL, NULL},
    {TPM_CC_ECC_Parameters, NULL, NULL, NULL},
    {TPM_CC_ZGen_2Phase, NULL, NULL, NULL},
    {TPM_CC_EncryptDecrypt, NULL, NULL, NULL},
    {TPM_CC_Hash, NULL, NULL, NULL},
    {TPM_CC_HMAC, NULL, NULL, NULL},
    {TPM_CC_GetRandom, NULL, NULL, NULL},
    {TPM_CC_StirRandom, NULL, NULL, NULL},
    {TPM_CC_HMAC_Start, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_HMAC_Start},
    {TPM_CC_HashSequenceStart, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_HashSequenceStart},
    {TPM_CC_SequenceUpdate, NULL, NULL, NULL},
    {TPM_CC_SequenceComplete, NULL,NULL, (TSS_PostProcessFunction_t)TSS_PO_SequenceComplete},
    {TPM_CC_EventSequenceComplete, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_EventSequenceComplete},
    {TPM_CC_Certify, NULL, NULL, NULL},
    {TPM_CC_CertifyCreation, NULL, NULL, NULL},
    {TPM_CC_Quote, NULL, NULL, NULL},
    {TPM_CC_GetSessionAuditDigest, NULL, NULL, NULL},
    {TPM_CC_GetCommandAuditDigest, NULL, NULL, NULL},
    {TPM_CC_GetTime, NULL, NULL, NULL},
    {TPM_CC_Commit, NULL, NULL, NULL},
    {TPM_CC_EC_Ephemeral, NULL, NULL, NULL},
    {TPM_CC_VerifySignature, NULL, NULL, NULL},
    {TPM_CC_Sign, NULL, NULL, NULL},
    {TPM_CC_SetCommandCodeAuditStatus, NULL, NULL, NULL},
    {TPM_CC_PCR_Extend, NULL, NULL, NULL},
    {TPM_CC_PCR_Event, NULL, NULL, NULL},
    {TPM_CC_PCR_Read, NULL, NULL, NULL},
    {TPM_CC_PCR_Allocate, NULL, NULL, NULL},
    {TPM_CC_PCR_SetAuthPolicy, NULL, NULL, NULL},
    {TPM_CC_PCR_SetAuthValue, NULL, NULL, NULL},
    {TPM_CC_PCR_Reset, NULL, NULL, NULL},
    {TPM_CC_PolicySigned, (TSS_PreProcessFunction_t)TSS_PR_PolicySigned, NULL, NULL},
    {TPM_CC_PolicySecret, NULL, NULL, NULL},
    {TPM_CC_PolicyTicket, NULL, NULL, NULL},
    {TPM_CC_PolicyOR, NULL, NULL, NULL},
    {TPM_CC_PolicyPCR, NULL, NULL, NULL},
    {TPM_CC_PolicyLocality, NULL, NULL, NULL},
    {TPM_CC_PolicyNV, NULL, NULL, NULL},
    {TPM_CC_PolicyCounterTimer, NULL, NULL, NULL},
    {TPM_CC_PolicyCommandCode, NULL, NULL, NULL},
    {TPM_CC_PolicyPhysicalPresence, NULL, NULL, NULL},
    {TPM_CC_PolicyCpHash, NULL, NULL, NULL},
    {TPM_CC_PolicyNameHash, NULL, NULL, NULL},
    {TPM_CC_PolicyDuplicationSelect, NULL, NULL, NULL},
    {TPM_CC_PolicyAuthorize, NULL, NULL, NULL},
    {TPM_CC_PolicyAuthValue, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_PolicyAuthValue},
    {TPM_CC_PolicyPassword, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_PolicyPassword},
    {TPM_CC_PolicyGetDigest, NULL, NULL, NULL},
    {TPM_CC_PolicyNvWritten, NULL, NULL, NULL},
    {TPM_CC_CreatePrimary, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_CreatePrimary},
    {TPM_CC_HierarchyControl, NULL, NULL, NULL},
    {TPM_CC_SetPrimaryPolicy, NULL, NULL, NULL},
    {TPM_CC_ChangePPS, NULL, NULL, NULL},
    {TPM_CC_ChangeEPS, NULL, NULL, NULL},
    {TPM_CC_Clear, NULL, NULL, NULL},
    {TPM_CC_ClearControl, NULL, NULL, NULL},
    {TPM_CC_HierarchyChangeAuth, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_HierarchyChangeAuth, NULL},
    {TPM_CC_DictionaryAttackLockReset, NULL, NULL, NULL},
    {TPM_CC_DictionaryAttackParameters, NULL, NULL, NULL},
    {TPM_CC_PP_Commands, NULL, NULL, NULL},
    {TPM_CC_SetAlgorithmSet, NULL, NULL, NULL},
    {TPM_CC_ContextSave, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_ContextSave},
    {TPM_CC_ContextLoad, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_ContextLoad},
    {TPM_CC_FlushContext, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_FlushContext},
    {TPM_CC_EvictControl, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_EvictControl},
    {TPM_CC_ReadClock, NULL, NULL, NULL},
    {TPM_CC_ClockSet, NULL, NULL, NULL},
    {TPM_CC_ClockRateAdjust, NULL, NULL, NULL},
    {TPM_CC_GetCapability, NULL, NULL, NULL},
    {TPM_CC_TestParms, NULL, NULL, NULL},
    {TPM_CC_NV_DefineSpace, (TSS_PreProcessFunction_t)TSS_PR_NV_DefineSpace, NULL, NULL},
    {TPM_CC_NV_UndefineSpace, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_UndefineSpace},
    {TPM_CC_NV_UndefineSpaceSpecial, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_NV_UndefineSpaceSpecial, (TSS_PostProcessFunction_t)TSS_PO_NV_UndefineSpaceSpecial},
    {TPM_CC_NV_ReadPublic, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_ReadPublic},
    {TPM_CC_NV_Write, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_Increment, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_Extend, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_SetBits, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_WriteLock, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_WriteLock},
    {TPM_CC_NV_GlobalWriteLock, NULL, NULL, NULL},
    {TPM_CC_NV_Read, NULL, NULL, NULL},
    {TPM_CC_NV_ReadLock, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_ReadLock},
    {TPM_CC_NV_ChangeAuth, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_NV_ChangeAuth, NULL},
    {TPM_CC_NV_Certify, NULL, NULL, NULL}
};

/* local prototypes */

static TPM_RC TSS_Context_Init(TSS_CONTEXT *tssContext);
static TPM_RC TSS_Execute_valist(TSS_CONTEXT *tssContext,
				 COMMAND_PARAMETERS *in,
				 va_list ap);


static TPM_RC TSS_PwapSession_Set(TPMS_AUTH_COMMAND *authCommand,
				  const char *password);
static TPM_RC TSS_PwapSession_Verify(TPMS_AUTH_RESPONSE *authResponse);

static TPM_RC TSS_HmacSession_GetContext(struct TSS_HMAC_CONTEXT **session);
static void   TSS_HmacSession_InitContext(struct TSS_HMAC_CONTEXT *session);
static void   TSS_HmacSession_FreeContext(struct TSS_HMAC_CONTEXT *session);

static TPM_RC TSS_HmacSession_SetSessionKey(TSS_CONTEXT *tssContext,
					    struct TSS_HMAC_CONTEXT *session,
					    TPM2B_DIGEST *salt,
					    TPMI_DH_ENTITY bind,
					    TPM2B_AUTH *bindAuthValue);
static TPM_RC TSS_HmacSession_SetNonceCaller(struct TSS_HMAC_CONTEXT *session,
					     TPMS_AUTH_COMMAND 	*authC);
static TPM_RC TSS_HmacSession_SetHmacKey(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 const char *password);
static TPM_RC TSS_HmacSession_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session[],
				      TPMS_AUTH_COMMAND *authCommand[],
				      TPMI_SH_AUTH_SESSION sessionHandle[],
				      unsigned int sessionAttributes[],
				      const char *password[],
				      TPM2B_NAME *name0,		  
				      TPM2B_NAME *name1,		  
				      TPM2B_NAME *name2);
static TPM_RC TSS_HmacSession_Verify(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session,
				     TPMS_AUTH_RESPONSE *authResponse);
static TPM_RC TSS_HmacSession_Continue(TSS_CONTEXT *tssContext,
				       struct TSS_HMAC_CONTEXT *session,
				       TPMS_AUTH_RESPONSE *authR);


static TPM_RC TSS_HmacSession_SaveSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_HmacSession_LoadSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session,
					  TPMI_SH_AUTH_SESSION	sessionHandle);
static uint16_t TSS_HmacSession_Marshal(struct TSS_HMAC_CONTEXT *source,
					uint16_t *written, uint8_t **buffer, int32_t *size);
static TPM_RC TSS_HmacSession_Unmarshal(struct TSS_HMAC_CONTEXT *target,
					uint8_t **buffer, int32_t *size);

static TPM_RC TSS_Name_GetAllNames(TSS_CONTEXT *tssContext,
				   TPM2B_NAME **names);
static TPM_RC TSS_Name_GetName(TSS_CONTEXT *tssContext,
			       TPM2B_NAME *name,
			       TPM_HANDLE  handle);
static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string);
static TPM_RC TSS_Name_Load(TSS_CONTEXT *tssContext,
			    TPM2B_NAME *name,
			    TPM_HANDLE handle,
			    const char *string);
static TPM_RC TSS_Name_Copy(TSS_CONTEXT *tssContext,
			    TPM_HANDLE outHandle,
			    const char *outString,
			    TPM_HANDLE inHandle,
			    const char *inString);
static TPM_RC TSS_Public_Store(TSS_CONTEXT *tssContext,
			       TPM2B_PUBLIC *public,
			       TPM_HANDLE handle,
			       const char *string);
static TPM_RC TSS_Public_Load(TSS_CONTEXT *tssContext,
			      TPM2B_PUBLIC *public,
			      TPM_HANDLE handle,
			      const char *string);
static TPM_RC TSS_Public_Copy(TSS_CONTEXT *tssContext,
			      TPM_HANDLE outHandle,
			      const char *outString,
			      TPM_HANDLE inHandle,
			      const char *inString);
static TPM_RC TSS_DeleteHandle(TSS_CONTEXT *tssContext,
			       TPM_HANDLE handle);

static TPM_RC TSS_NVPublic_Store(TSS_CONTEXT *tssContext,
				 TPMS_NV_PUBLIC *nvPublic,
				 TPMI_RH_NV_INDEX handle);
static TPM_RC TSS_NVPublic_Load(TSS_CONTEXT *tssContext,
				TPMS_NV_PUBLIC *nvPublic,
				TPMI_RH_NV_INDEX handle);
static TPM_RC TSS_NVPublic_Delete(TSS_CONTEXT *tssContext,
				  TPMI_RH_NV_INDEX nvIndex);


static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  struct TSS_HMAC_CONTEXT *session[],
				  TPMI_SH_AUTH_SESSION sessionHandle[],
				  unsigned int sessionAttributes[]);
static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_Command_DecryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session);

static TPM_RC TSS_Response_Encrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				   struct TSS_HMAC_CONTEXT *session[],
				   TPMI_SH_AUTH_SESSION sessionHandle[],
				   unsigned int sessionAttributes[]);
static TPM_RC TSS_Response_EncryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_Response_EncryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session);

static TPM_RC TSS_Command_ChangeAuthProcessor(TSS_CONTEXT *tssContext,
					      struct TSS_HMAC_CONTEXT *session,
					      size_t handleNumber,
					      COMMAND_PARAMETERS *in);
static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA_PARAMETERS *extra);
static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA_PARAMETERS *extra);

static TPM_RC TSS_Sessions_GetDecryptSession(unsigned int *isDecrypt,
					     unsigned int *decryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[]);
static TPM_RC TSS_Sessions_GetEncryptSession(unsigned int *isEncrypt,
					     unsigned int *encryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[]);

static TPM_RC TSS_HashToString(char *str, uint8_t *digest);

extern int tssVerbose;
extern int tssVverbose;
extern int tssFirstCall;

TPM_RC TSS_Create(TSS_CONTEXT **tssContext)
{
    TPM_RC		rc = 0;

    /* allocate the high level TSS structure */
    if (rc == 0) {
	*tssContext = malloc(sizeof(TSS_CONTEXT));
	if (*tssContext == NULL) {
	    if (tssVerbose) printf("TSS_Create: malloc %u failed\n",
				   (unsigned int)sizeof(TSS_CONTEXT));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* initialize the high level TSS structure */
    if (rc == 0) {
	rc = TSS_Context_Init(*tssContext);
	/* the likely cause of a failure is a bad environment variable */
	if (rc != 0) {
	    if (tssVerbose) printf("TSS_Create: TSS_Context_Init() failed\n");
	    free(*tssContext);
	    *tssContext = NULL;
	}
    }
    /* allocate and initialize the lower layer TSS context */
    if (rc == 0) {
	rc = TSS_AuthCreate(&((*tssContext)->tssAuthContext));
    }
    return rc;
}

/* TRUE if the TSS has never been called.  Used for any global library initialization.  */

static TPM_RC TSS_Context_Init(TSS_CONTEXT *tssContext)
{
    TPM_RC		rc = 0;

    /* at the first call to the TSS, initialize global variables */
    if (tssFirstCall) {
	/* crypto module initializations */
	if (rc == 0) {
	    rc = TSS_Crypto_Init();
	}
	if (rc == 0) {
	    rc = TSS_GlobalProperties_Init();
	}
	tssFirstCall = FALSE;
    }
    if (rc == 0) {
	rc = TSS_Properties_Init(tssContext);
    }
    return rc;
}

TPM_RC TSS_Delete(TSS_CONTEXT *tssContext)
{
    TPM_RC rc = 0;

    if (tssContext != NULL) {
	TSS_AuthDelete(tssContext->tssAuthContext);
	rc = TSS_Close(tssContext);
	free(tssContext);
    }
    return rc;
}

/* TSS_Execute() performs the complete command / response process.

   It sends the command specified by commandCode and the parameters 'in', returning the response
   parameters 'out'.

   ... varargs are

   TPMI_SH_AUTH_SESSION sessionHandle,
   const char *password,
   unsigned int sessionAttributes

   Terminates with TPM_RH_NULL, NULL, 0

   Processes up to MAX_SESSION_NUM sessions.
*/

TPM_RC TSS_Execute(TSS_CONTEXT *tssContext,
		   RESPONSE_PARAMETERS *out,
		   COMMAND_PARAMETERS *in,
		   EXTRA_PARAMETERS *extra,
		   TPM_CC commandCode,
		   ...)
{
    TPM_RC		rc = 0;
    va_list		ap;

    /* create a TSS context */
    if (rc == 0) {
	TSS_InitAuthContext(tssContext->tssAuthContext);
    }
    if (rc == 0) {
	rc = TSS_Command_PreProcessor(tssContext,
				      commandCode,
				      in,
				      extra);
    }
    /* marshal input parameters */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute: Command %08x marshal\n", commandCode);
	rc = TSS_Marshal(tssContext->tssAuthContext,
			 in,
			 commandCode);
    }
    /* execute the command */
    if (rc == 0) {
	va_start(ap, commandCode);
	rc = TSS_Execute_valist(tssContext, in, ap);
	va_end(ap);
    }
    /* unmarshal the response parameters */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute: Command %08x unmarshal\n", commandCode);
	rc = TSS_Unmarshal(tssContext->tssAuthContext, out);
    }
    /* handle any command specific response post-processing */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute: Command %08x post processor\n", commandCode);
	rc = TSS_Response_PostProcessor(tssContext,
					in,
					out,
					extra);
    }
    return rc;
}

/* TSS_Execute_valist() transmits the marshaled command and receives the marshaled response.

   varargs are TPMI_SH_AUTH_SESSION sessionHandle, const char *password, unsigned int
   sessionAttributes

   Terminates with sessionHandle TPM_RH_NULL

   Processes up to MAX_SESSION_NUM sessions.  It handles HMAC generation and command and response
   parameter encryption.  It loads each session context, rolls nonces, and saves or deletes the
   session context.
*/

static TPM_RC TSS_Execute_valist(TSS_CONTEXT *tssContext,
				 COMMAND_PARAMETERS *in,
				 va_list ap)
{
    TPM_RC		rc = 0;
    int 		done;
    int 		haveNames = FALSE;	/* names are common to all HMAC sessions */
    unsigned int	i = 0;

    /* the vararg parameters */
    TPMI_SH_AUTH_SESSION sessionHandle[MAX_SESSION_NUM];
    const char 		*password[MAX_SESSION_NUM];
    unsigned int	sessionAttributes[MAX_SESSION_NUM]; 

    /* structures filled in */
    TPMS_AUTH_COMMAND 	authCommand[MAX_SESSION_NUM];
    TPMS_AUTH_RESPONSE 	authResponse[MAX_SESSION_NUM];
    
    /* pointer to the above structures as used */
    TPMS_AUTH_COMMAND 	*authC[MAX_SESSION_NUM];
    TPMS_AUTH_RESPONSE 	*authR[MAX_SESSION_NUM];

    /* TSS sessions */
    struct TSS_HMAC_CONTEXT *session[MAX_SESSION_NUM];
    TPM2B_NAME authName[MAX_SESSION_NUM];
    TPM2B_NAME *names[MAX_SESSION_NUM];
	
    /* Step 1: initialization */
    if (tssVverbose) printf("TSS_Execute_valist: Step 1: initialization\n");
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) ; i++) {
	authC[i] = NULL;		/* array of TPMS_AUTH_COMMAND structures, NULL for
					   TSS_SetCmdAuths */
	authR[i] = NULL;		/* array of TPMS_AUTH_RESPONSE structures, NULL for
					   TSS_GetRspAuths */
	session[i] = NULL;		/* for free, used for HMAC and encrypt/decrypt sessions */
	names[i] = &authName[i];	/* array of TPM2B_NAME pointers */
	authName[i].b.size = 0;		/* to ignore unused names in cpHash calculation */
	/* the varargs list inputs */
	sessionHandle[i] = TPM_RH_NULL;
	password[i] = NULL;
	sessionAttributes[i] = 0;
    }
    /* Step 2: gather the command authorizations

       Process PWAP immediately
       For HMAC, get the session context
    */
    done = FALSE;
    for (i = 0 ; (rc == 0) && !done && (i < MAX_SESSION_NUM) ; i++) {
 	sessionHandle[i] = va_arg(ap, TPMI_SH_AUTH_SESSION);	/* first vararg is the session
								   handle */
	password[i]= va_arg(ap, const char *);			/* second vararg is the password */
	sessionAttributes[i] = va_arg(ap, unsigned int);	/* third argument is
								   sessionAttributes */
	sessionAttributes[i] &= 0xff;				/* is uint8_t */

	if (sessionHandle[i] != TPM_RH_NULL) {			/* varargs termination value */ 

	    if (tssVverbose) printf("TSS_Execute_valist: Step 2: authorization %u\n", i);
	    if (tssVverbose) printf("TSS_Execute_valist: session %u handle %08x\n",
				    i, sessionHandle[i]);
	    /* make used, non-NULL for command and response varargs */
	    authC[i] = &authCommand[i];
	    authR[i] = &authResponse[i];

	    /* if password session, populate authC with password, etc. immediately */
	    if (sessionHandle[i] == TPM_RS_PW) {
		rc = TSS_PwapSession_Set(authC[i], password[i]);
	    }
	    /* if HMAC or encrypt/decrypt session  */
	    else {
		/* if there is at least one HMAC session, get the names corresponding to the
		   handles */
		if ((rc == 0) && !haveNames) {
		    rc = TSS_Name_GetAllNames(tssContext, names);
		    haveNames = TRUE;	/* get only once, minor optimization */
		}
		/* initialize a TSS HMAC session */
		if (rc == 0) {
		    rc = TSS_HmacSession_GetContext(&session[i]);
		}
		/* load the session created by startauthsession */
		if (rc == 0) {
		    rc = TSS_HmacSession_LoadSession(tssContext, session[i], sessionHandle[i]);
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }
    /* Step 3: Roll nonceCaller, save in the session context for the response */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {		/* no nonce for password sessions */
	    if (tssVverbose)
		printf("TSS_Execute_valist: Step 3: nonceCaller %08x\n", sessionHandle[i]);
	    rc = TSS_HmacSession_SetNonceCaller(session[i], authC[i]);
	}
    }
    /* Step 4: Calculate the HMAC key */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {		/* no HMAC key for password sessions */
	    if (tssVverbose) printf("TSS_Execute_valist: Step 4 HMAC key %08x\n", sessionHandle[i]);
	    rc = TSS_HmacSession_SetHmacKey(tssContext, session[i], i, password[i]);
	}
    }
    /* Step 5: command parameter encryption */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 5: command encrypt\n");
	rc = TSS_Command_Decrypt(tssContext->tssAuthContext,
				 session,
				 sessionHandle,
				 sessionAttributes);
    }
    /* Step 6: for each HMAC session, calculate cpHash, calculate the HMAC, and set it in
       TPMS_AUTH_COMMAND */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 6 calculate HMACs\n");
	rc = TSS_HmacSession_SetHMAC(tssContext->tssAuthContext,	/* TSS auth context */
				     session,		/* TSS session contexts */
				     authC,		/* output: command authorizations */
				     sessionHandle,	/* list of session handles for the command */
				     sessionAttributes, /* attributes for this command */
				     password,		/* for plaintext password sessions */
				     names[0],		/* Name */
				     names[1],		/* Name */
				     names[2]);		/* Name */
    }
    /* Step 7: set the command authorizations in the TSS command stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 7 set command authorizations\n");
	rc = TSS_SetCmdAuths(tssContext->tssAuthContext,
			     authC[0],
			     authC[1],
			     authC[2],
			     NULL);
    }
    /* Step 8: process the command.  Normally returns the TPM response code. */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 8: process the command\n");
	rc = TSS_AuthExecute(tssContext);
    }
    /* Step 9: get the response authorizations from the TSS response stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 9 get response authorizations\n");
	rc = TSS_GetRspAuths(tssContext->tssAuthContext,
			     authR[0],
			     authR[1],
			     authR[2],
			     NULL);
    }
    /* Step 10: process the response authorizations, validate the HMAC */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (tssVverbose)
	    printf("TSS_Execute_valist: Step 10: process response authorization %08x\n",
		   sessionHandle[i]);
	if (sessionHandle[i] == TPM_RS_PW) {
	    rc = TSS_PwapSession_Verify(authR[i]);
	}
	/* HMAC session */
	else {
	    /* save nonceTPM in the session context */
	    if (rc == 0) {
		rc = TSS_TPM2B_Copy(&session[i]->nonceTPM.b, &authR[i]->nonce.b, sizeof(TPMU_HA));
	    }
	    /* the HMAC key is already part of the TSS session context.  For policy sessions with
	       policy password, the response hmac is empty. */
	    if ((session[i]->sessionType == TPM_SE_HMAC) ||
		((session[i]->sessionType == TPM_SE_POLICY) && (session[i]->isAuthValueNeeded))) {
	    
		if (rc == 0) {
		    rc = TSS_Command_ChangeAuthProcessor(tssContext, session[i], i, in);
		}
		if (rc == 0) {
		    rc = TSS_HmacSession_Verify(tssContext->tssAuthContext,	/* authorization context */
						session[i],	/* TSS session context */
						authR[i]);	/* input: response authorization */
		}
	    }
	}
    }
    /* Step 11: process the audit flag */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if ((sessionHandle[i] != TPM_RS_PW) &&
	    (session[i]->bind != TPM_RH_NULL) &&
	    (authR[i]->sessionAttributes.val & TPMA_SESSION_AUDIT)) {
	    if (tssVverbose) printf("TSS_Execute_valist: Step 11: process bind audit flag %08x\n",
				    sessionHandle[i]);
	    /* if bind audit session, bind value is lost and further use requires authValue */
	    session[i]->bind = TPM_RH_NULL;
	}
    }
    /* Step 12: process the response continue flag */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {
	    if (tssVverbose) printf("TSS_Execute_valist: Step 12: process continue flag %08x\n",
				    sessionHandle[i]);
	    rc = TSS_HmacSession_Continue(tssContext, session[i], authR[i]);
	}
    }
    /* Step 13: response parameter decryption */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 13: response decryption\n");
	rc = TSS_Response_Encrypt(tssContext->tssAuthContext,
				  session,
				  sessionHandle,
				  sessionAttributes);
    }
    /* cleanup */
    for (i = 0 ; i < MAX_SESSION_NUM ; i++) {
	TSS_HmacSession_FreeContext(session[i]);
    }
    return rc;
}

/*
  PWAP
*/

/* TSS_PwapSession_Set() sets all members of the TPMS_AUTH_COMMAND structure for a PWAP session.
 */

static TPM_RC TSS_PwapSession_Set(TPMS_AUTH_COMMAND *authCommand,
				  const char *password)
{
    TPM_RC		rc = 0;
    
    if (rc == 0) {
	authCommand->sessionHandle = TPM_RS_PW;
	authCommand->nonce.t.size = 0;
	authCommand->sessionAttributes.val = 0;
    }
    if (password != NULL) {
	rc = TSS_TPM2B_StringCopy(&authCommand->hmac.b, password, sizeof(TPMU_HA));
    }
    else {
	authCommand->hmac.t.size = 0;
    }
    return rc;
}

static TPM_RC TSS_PwapSession_Verify(TPMS_AUTH_RESPONSE *authResponse)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	if (authResponse->nonce.t.size != 0) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: nonce size %u not zero\n",
				   authResponse->nonce.t.size);
	    rc = TSS_RC_BAD_PWAP_NONCE;
	}
    }
    if (rc == 0) {
	if (authResponse->sessionAttributes.val != TPMA_SESSION_CONTINUESESSION) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: continue %02x not set\n",
				   authResponse->sessionAttributes.val);
	    rc = TSS_RC_BAD_PWAP_ATTRIBUTES;
	}
    }
    if (rc == 0) {
	if (authResponse->hmac.t.size != 0) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: HMAC size %u not zero\n",
				   authResponse->hmac.t.size);
	    rc = TSS_RC_BAD_PWAP_HMAC;
	}
    }
    return rc;
}

/*
  HMAC Session
*/

static TPM_RC TSS_HmacSession_GetContext(struct TSS_HMAC_CONTEXT **session)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	*session = malloc(sizeof(TSS_HMAC_CONTEXT));
	if (*session == NULL) {
	    if (tssVerbose) printf("TSS_HmacSession_GetContext: malloc %u failed\n",
				   (unsigned int)sizeof(TSS_HMAC_CONTEXT));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	TSS_HmacSession_InitContext(*session);
    }
    return rc;
}

static void TSS_HmacSession_InitContext(struct TSS_HMAC_CONTEXT *session)
{
    session->sessionHandle = TPM_RH_NULL;
    session->authHashAlg = TPM_ALG_NULL;
    session->sizeInBytes = 0;
    session->symmetric.algorithm = TPM_ALG_NULL;
    session->bind = TPM_RH_NULL;
    session->bindName.b.size = 0;
    session->bindAuthValue.t.size = 0;
    memset(session->nonceTPM.t.buffer, 0, sizeof(TPMU_HA));
    session->nonceTPM.b.size = 0;
    memset(session->nonceCaller.t.buffer, 0, sizeof(TPMU_HA));
    session->nonceCaller.b.size = 0;
    memset(session->sessionKey.t.buffer, 0, sizeof(TPMU_HA));
    session->sessionKey.b.size = 0;
    session->sessionType = 0;
    session->isPasswordNeeded = FALSE;
    session->isAuthValueNeeded = FALSE;
    memset(session->hmacKey.t.buffer, 0, sizeof(TPMU_HA) + sizeof(TPMU_HA));
    session->hmacKey.b.size = 0;
    memset(session->sessionValue.t.buffer, 0, sizeof(TPMU_HA) + sizeof(TPMU_HA));
    session->sessionValue.b.size = 0;
}

void TSS_HmacSession_FreeContext(struct TSS_HMAC_CONTEXT *session)
{
    if (session!= NULL) {
	TSS_HmacSession_InitContext(session);
	free(session);
    }
    return;
}

/* TSS_HmacSession_SetSessionKey() is called by the StartAuthSession post processor to calculate and
   store the session key

   19.6.8	sessionKey Creation
*/

static TPM_RC TSS_HmacSession_SetSessionKey(TSS_CONTEXT *tssContext,
					    struct TSS_HMAC_CONTEXT *session,
					    TPM2B_DIGEST *salt,
					    TPMI_DH_ENTITY bind,
					    TPM2B_AUTH *bindAuthValue)
{
    TPM_RC		rc = 0;
    TPM2B_KEY 		key;		/* HMAC key for the KDFa */

    if (rc == 0) {
	/* save the bind handle, non-null indicates a bound session */
	session->bind = bind;
	/* if bind, save the bind Name in the session context.  The handle might change, but the
	   name will not */
	if ((rc == 0) && (bind != TPM_RH_NULL)) {
	    rc = TSS_Name_GetName(tssContext, &session->bindName, bind);
	}
    }
    if (rc == 0) {
        if ((bind != TPM_RH_NULL) ||
	    (salt->b.size != 0)) {

	    /* session key is bindAuthValue || salt */
	    /* copy bindAuthValue.  This is set during the preprocessor to either the supplied bind
	       password */
	    if (rc == 0) {
		rc = TSS_TPM2B_Copy(&key.b, &bindAuthValue->b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	    /* copy salt.  This is set during the postprocessor to either the salt from the
	       preprocessor or empty. */
	    if (rc == 0) {
		rc = TSS_TPM2B_Append(&key.b, &salt->b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	    if (rc == 0) {
		if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetSessionKey: KDFa HMAC key",
					      key.b.buffer, key.b.size);
	    }
	    /* KDFa for the session key */
	    if (rc == 0) {
		uint32_t	counterInOut = 0;
		session->sessionKey.b.size = 
		    _cpri__KDFa(session->authHashAlg,
				&key.b,
				"ATH",
				&session->nonceTPM.b,
				&session->nonceCaller.b,
				session->sizeInBytes * 8,
				session->sessionKey.b.buffer,
				&counterInOut,
				FALSE);
		if (session->sessionKey.b.size == 0) {
		    if (tssVerbose) printf("TSS_HmacSession_SetSessionKey: KDFa failed\n");
		    rc = TSS_RC_KDFA_FAILED;
		}
	    }
	    if (rc == 0) {
		if (tssVverbose)
		    TSS_PrintAll("TSS_HmacSession_SetSessionKey: Session key",
				 session->sessionKey.b.buffer, session->sessionKey.b.size);
	    }
	}
	else {
	    session->sessionKey.b.size = 0;
	}
    }
    return rc;
}

/* TSS_HmacSession_SaveSession() saves a session in two cases:

   The initial session from startauthsession
   The updated session a TPM response
*/

static TPM_RC TSS_HmacSession_SaveSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC	rc = 0;
    uint8_t 	*buffer = NULL;
    uint8_t	*buffer1 = NULL;	/* for marshaling */
    uint16_t	written = 0;
    char	sessionFilename[128];

    unsigned char *outBuffer = NULL; /* output, caller frees */
    uint32_t outLength;

    if (rc == 0) {
	/* save the session in a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
	   handle */
	sprintf(sessionFilename, "%s/h%08x.bin",
		tssContext->tssDataDirectory, session->sessionHandle);
	/* calculate the marshaled size */
	written = 0;
	rc = TSS_HmacSession_Marshal(session, &written, NULL, NULL);
    }
    if (rc == 0) {
	buffer = realloc(buffer, written);
	buffer1 = buffer;
	written = 0;
	rc = TSS_HmacSession_Marshal(session, &written, &buffer1, NULL);
    }
    if (rc == 0) {
	/* encrypt session state before store */
	if (tssContext->tssEncryptSessions) {
	    rc = TSS_AES_Encrypt(&outBuffer,   	/* output, caller frees */
				 &outLength,	/* output */
				 buffer,	/* input */
				 written);	/* input */
	}
	/* store session state in plaintext */
	else {
	    outBuffer = buffer;
	    outLength = written;
	}
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(outBuffer,
				      outLength,
				      sessionFilename);
    }
    free(buffer);
    if (tssContext->tssEncryptSessions) {
	free(outBuffer);
    }
    return rc;
}

/* TSS_HmacSession_LoadSession() loads an HMAC existing session saved by:

   startauthsession
   an update after a TPM response
*/

static TPM_RC TSS_HmacSession_LoadSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session,
					  TPMI_SH_AUTH_SESSION	sessionHandle)
{
    TPM_RC		rc = 0;
    uint8_t 		*buffer = NULL;
    uint8_t 		*buffer1 = NULL;
    size_t 		length = 0;
    char		sessionFilename[128];
    
    unsigned char *inData = NULL;		/* output, caller frees */
    uint32_t inLength;				/* output */

    if (tssVverbose) printf("TSS_HmacSession_LoadSession: handle %08x\n", sessionHandle);
    /* load the session from a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
       handle */
    if (rc == 0) {
	sprintf(sessionFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, sessionHandle);
	rc = TSS_File_ReadBinaryFile(&buffer,     /* must be freed by caller */
				     &length,
				     sessionFilename);
    }
    if (rc == 0) {
	/* decrypt session state before unmarshal */
	if (tssContext->tssEncryptSessions) {
	    rc = TSS_AES_Decrypt(&inData,   	/* output, caller frees */
				 &inLength,	/* output */
				 buffer,	/* input */
				 length);	/* input */
	}
	/* session loaded in plaintext */
	else {
	    inData = buffer;
	    inLength = length;
	}
    }
    if (rc == 0) {
	int32_t ilength = inLength;
	buffer1 = inData;
	rc = TSS_HmacSession_Unmarshal(session, &buffer1, &ilength);
    }
    free(buffer);
    if (tssContext->tssEncryptSessions) {
	free(inData);
    }
    return rc;
}

static uint16_t TSS_HmacSession_Marshal(struct TSS_HMAC_CONTEXT *source,
					uint16_t *written,
					uint8_t **buffer,
					int32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Marshal(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshal(&source->authHashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshal(&source->sizeInBytes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_Marshal(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshal(&source->bind, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshal(&source->bindName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshal(&source->bindAuthValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshal(&source->nonceCaller, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshal(&source->sessionKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_SE_Marshal(&source->sessionType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->isPasswordNeeded, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshal(&source->isAuthValueNeeded, written, buffer, size);
    }
    return rc;
}

static TPM_RC TSS_HmacSession_Unmarshal(struct TSS_HMAC_CONTEXT *target,
					uint8_t **buffer, int32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TPMI_SH_AUTH_SESSION_Unmarshal(&target->sessionHandle, buffer, size, NO);
    }
    if (rc == 0) {
	rc = TPMI_ALG_HASH_Unmarshal(&target->authHashAlg, buffer, size, NO);
    }
    if (rc == 0) {
	rc = UINT32_Unmarshal(&target->sizeInBytes, buffer, size);
    }
    if (rc == 0) {
	rc = TPMT_SYM_DEF_Unmarshal(&target->symmetric, buffer, size, YES);
    }
    if (rc == 0) {
	rc = TPMI_DH_ENTITY_Unmarshal(&target->bind, buffer, size, YES);
    }
    if (rc == 0) {
	rc = TPM2B_NAME_Unmarshal(&target->bindName, buffer, size);
    }
    if (rc == 0) {
	rc = TPM2B_AUTH_Unmarshal(&target->bindAuthValue, buffer, size);
    }
    if (rc == 0) {
	rc = TPM2B_NONCE_Unmarshal(&target->nonceTPM, buffer, size);
    }
    if (rc == 0) {
	rc = TPM2B_NONCE_Unmarshal(&target->nonceCaller, buffer, size);
    }
    if (rc == 0) {
	rc = TPM2B_DIGEST_Unmarshal(&target->sessionKey, buffer, size);
    }
    if (rc == 0) {
	rc = TPM_SE_Unmarshal(&target->sessionType, buffer, size);
    }
    if (rc == 0) {
	rc = UINT8_Unmarshal(&target->isPasswordNeeded, buffer, size);
    }
    if (rc == 0) {
	rc = UINT8_Unmarshal(&target->isAuthValueNeeded, buffer, size);
    }
    return rc;
}

/*
  Name handling
*/

/* TSS_Name_GetAllNames() files in the names array based on the handles marshaled into the TSS
   context command stream. */

static TPM_RC TSS_Name_GetAllNames(TSS_CONTEXT *tssContext,
				   TPM2B_NAME **names)
{
    TPM_RC	rc = 0;
    uint32_t 	i;
    uint32_t 	commandHandleCount;	/* number of handles in the command stream */
    TPM_HANDLE  commandHandle;

    /* get the number of handles in the command stream */
    if (rc == 0) {
	rc = TSS_GetCommandHandleCount(tssContext->tssAuthContext, &commandHandleCount);	      
	if (tssVverbose) printf("TSS_Name_GetAllNames: commandHandleCount %u\n", commandHandleCount);
    }
    for (i = 0 ; i < commandHandleCount ; i++) {
	/* get a handle from the command stream */
	if (rc == 0) {
	    rc = TSS_GetCommandHandle(tssContext->tssAuthContext,
				      &commandHandle,
				      i);
	}
	/* get the Name corresponding to the handle */
	if (rc == 0) {
	    if (tssVverbose) printf("TSS_Name_GetAllNames: commandHandle %u %08x\n",
				    i, commandHandle);
	    rc = TSS_Name_GetName(tssContext, names[i], commandHandle);
	}
    }
    return rc;
}

/* TSS_Name_GetName() gets the Name associated with the handle */

static TPM_RC TSS_Name_GetName(TSS_CONTEXT *tssContext,
			       TPM2B_NAME *name,
			       TPM_HANDLE  handle)
{
    TPM_RC	rc = 0;
    TPM_HT 	handleType;

    if (tssVverbose) printf("TSS_Name_GetName: Handle %08x\n", handle);
    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);

    /* Table 3 - Equations for Computing Entity Names */
    switch (handleType) {
	/* for these, the Name is simply the handle value */
      case TPM_HT_PCR:
      case TPM_HT_HMAC_SESSION:
      case TPM_HT_POLICY_SESSION:
      case TPM_HT_PERMANENT:
	rc = TSS_TPM2B_CreateUint32(&name->b, handle, sizeof(TPMU_NAME));
	break;
	/* for NV, the Names was calculated at NV read public */
      case TPM_HT_NV_INDEX:
	/* for objects, the Name was returned at creation or load */
      case TPM_HT_TRANSIENT:
      case TPM_HT_PERSISTENT:
	rc = TSS_Name_Load(tssContext, name, handle, NULL);
	break;
      default:
	break;
	if (tssVerbose) printf("TSS_Name_GetName: not implemented for handle %08x\n", handle);
	rc = TSS_RC_NAME_NOT_IMPLEMENTED;
    }
    return rc;
}

/* TSS_Name_Store() stores the 'name' parameter in a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/

static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string)
{
    TPM_RC 	rc = 0;
    char 	nameFilename[128];

    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(nameFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Store: handle and string are both null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(nameFilename, "%s/h%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Store: handle and string are both not null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Name_Store: File %s\n", nameFilename);
	rc = TSS_File_WriteBinaryFile(name->b.buffer, name->b.size, nameFilename);
    }
    return rc;
}

/* TSS_Name_Load() loads the 'name' from a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/
   
static TPM_RC TSS_Name_Load(TSS_CONTEXT *tssContext,
			    TPM2B_NAME *name,
			    TPM_HANDLE handle,
			    const char *string)
{
    TPM_RC 		rc = 0;
    char 		nameFilename[128];
		
    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(nameFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Load: handle and string are both null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(nameFilename, "%s/h%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Load: handle and string are both not null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Name_Load: File %s\n", nameFilename);
	rc = TSS_File_Read2B(&name->b,
			     sizeof(TPMU_NAME),
			     nameFilename);
    }
    return rc;
}

/* TSS_Name_Copy() copies the name from either inHandle or inString to either outHandle or
   outString */

static TPM_RC TSS_Name_Copy(TSS_CONTEXT *tssContext,
			    TPM_HANDLE outHandle,
			    const char *outString,
			    TPM_HANDLE inHandle,
			    const char *inString)
{
    TPM_RC 		rc = 0;
    TPM2B_NAME 		name;
    
    if (rc == 0) {
	rc = TSS_Name_Load(tssContext, &name, inHandle, inString);
    }
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &name, outHandle, outString);
    }
    return rc;
}

/* TSS_Public_Store() stores the 'public' parameter in a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/

static TPM_RC TSS_Public_Store(TSS_CONTEXT *tssContext,
			       TPM2B_PUBLIC *public,
			       TPM_HANDLE handle,
			       const char *string)
{
    TPM_RC 	rc = 0;
    char 	publicFilename[128];

    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(publicFilename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(publicFilename, "%s/hp%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both not null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Public_Store: File %s\n", publicFilename);
	rc = TSS_File_WriteStructure(public,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				     publicFilename);
    }
    return rc;
}

/* TSS_Public_Load() loads the 'public' parameter from a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/
   
static TPM_RC TSS_Public_Load(TSS_CONTEXT *tssContext,
			      TPM2B_PUBLIC *public,
			      TPM_HANDLE handle,
			      const char *string)
{
    TPM_RC 		rc = 0;
    char 		publicFilename[128];
		
    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(publicFilename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(publicFilename, "%s/hp%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both not null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Public_Load: File %s\n", publicFilename);
	rc = TSS_File_ReadStructure(public,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    publicFilename);
    }
    return rc;
}

/* TSS_Public_Copy() copies the TPM2B_PUBLIC from either inHandle or inString to either outHandle or
   outString */

static TPM_RC TSS_Public_Copy(TSS_CONTEXT *tssContext,
			      TPM_HANDLE outHandle,
			      const char *outString,
			      TPM_HANDLE inHandle,
			      const char *inString)
{
    TPM_RC 		rc = 0;
    TPM2B_PUBLIC 	public;
    
    if (rc == 0) {
	rc = TSS_Public_Load(tssContext, &public, inHandle, inString);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &public, outHandle, outString);
    }
    return rc;
}

/* TSS_DeleteHandle() removes persistent state for a handle stored by the TSS
 */

TPM_RC TSS_DeleteHandle(TSS_CONTEXT *tssContext,
			TPM_HANDLE handle)
{
    TPM_RC		rc = 0;
    char		filename[128];

    /* delete the name */
    if (rc == 0) {
	sprintf(filename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	if (tssVverbose) printf("TSS_DeleteHandle: delete handle file %s\n", filename);
	rc = TSS_File_DeleteFile(filename);
    }
    /* delete the public if it exists */
    if (rc == 0) {
	sprintf(filename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	if (tssVverbose) printf("TSS_DeleteHandle: delete public file %s\n", filename);
	TSS_File_DeleteFile(filename);
    }
    return rc;
}

static TPM_RC TSS_NVPublic_Store(TSS_CONTEXT *tssContext,
				 TPMS_NV_PUBLIC *nvPublic,
				 TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[128];

    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_WriteStructure(nvPublic,
				     (MarshalFunction_t)TSS_TPMS_NV_PUBLIC_Marshal,
				     nvpFilename);
    }
    return rc;
}

static TPM_RC TSS_NVPublic_Load(TSS_CONTEXT *tssContext,
				TPMS_NV_PUBLIC *nvPublic,
				TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[128];

    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_ReadStructure(nvPublic,
				    (UnmarshalFunction_t)TPMS_NV_PUBLIC_Unmarshal,
				    nvpFilename);
    }
    return rc;
}

static TPM_RC TSS_NVPublic_Delete(TSS_CONTEXT *tssContext,
				  TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[128];
    
    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_DeleteFile(nvpFilename);
	return rc;    
    }
    return rc;
}

/* TSS_NVPublic_GetName() calculates the Name from the TPMS_NV_PUBLIC.  The Name provides security,
   because the Name returned from the TPM cannot be trusted.
*/

static TPM_RC TSS_NVPublic_GetName(TPM2B_NAME *name,
				   TPMS_NV_PUBLIC *nvPublic)
{
    TPM_RC 	rc = 0;
    uint16_t 	written = 0;
    uint8_t 	buffer[MAX_RESPONSE_SIZE];
    uint32_t 	sizeInBytes;
    TPMT_HA	digest;
    
    /* marshal the TPMS_NV_PUBLIC */
    if (rc == 0) {
	INT32 size = MAX_RESPONSE_SIZE;
	uint8_t *buffer1 = buffer;
	rc = TSS_TPMS_NV_PUBLIC_Marshal(nvPublic, &written, &buffer1, &size);
    }
    /* hash the public area */
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(nvPublic->nameAlg);
	digest.hashAlg = nvPublic->nameAlg;	/* Name digest algorithm */
	/* generate the TPMT_HA */
	rc = TSS_Hash_Generate(&digest,	
			       written, buffer,
			       0, NULL);
    }
    if (rc == 0) {
	/* copy the digest */
	memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
	/* copy the hash algorithm */
	TPMI_ALG_HASH nameAlgNbo = htons(nvPublic->nameAlg);
	memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
	/* set the size */
	name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
    }
    return rc;
}

static TPM_RC TSS_HmacSession_SetNonceCaller(struct TSS_HMAC_CONTEXT *session,
					     TPMS_AUTH_COMMAND 	*authC)
{
    TPM_RC		rc = 0;

    /* generate a new nonceCaller */
    if (rc == 0) {
	session->nonceCaller.b.size = session->sizeInBytes;
	rc = TSS_RandBytes(session->nonceCaller.t.buffer,session->sizeInBytes);
    }
    /* nonceCaller for the command */
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&authC->nonce.b, &session->nonceCaller.b, sizeof(TPMU_HA));
    }
    return rc;
}

/* TSS_HmacSession_SetHmacKey() calculates the session HMAC key.

   handleNumber is index into the session area.  The first sessions, the authorization sessions,
   have a corresponding handle in the command handle.
*/

static TPM_RC TSS_HmacSession_SetHmacKey(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 const char *password)
{
    TPM_RC		rc = 0;
    TPM_HANDLE 		commandHandle;		/* from handle area, for bound session */
    TPM2B_NAME		name;
    TPM2B_AUTH 		authValue;
    int 		bindMatch = FALSE;
    int 		done = FALSE;		/* done with authorization sessions */

    /*
      authHMAC = HMACsessionAlg ((sessionKey || authValue), 
      (pHash || nonceNewer || nonceOlder 
      { || nonceTPMdecrypt } { || nonceTPMencrypt }
      || sessionAttributes))
    */
    /* HMAC key is sessionKey || authValue */
    /* copy the session key to HMAC key */
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetHmacKey: sessionKey",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	rc = TSS_TPM2B_Copy(&session->hmacKey.b,
			    &session->sessionKey.b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
    }
    /* copy the session key to sessionValue */
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->sessionValue.b,
			    &session->sessionKey.b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
    }
    if (rc == 0) {
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: preliminary sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
    }
    /* This value is an EmptyAuth if the HMAC is being computed to authorize an action on the
       object to which the session is bound.
    */
    /* The first sessions are authorization sessions.  They can have a bind entity.  All others can
       be encrypt or decrypt sessions, but the authValue is not included in the session key.
    */
    if (rc == 0) {
	AUTH_ROLE authRole = TSS_GetAuthRole(tssContext->tssAuthContext, handleNumber);
	if (authRole == AUTH_NONE) {
	    if (tssVverbose) printf("TSS_HmacSession_SetHmacKey: Done, not auth session\n");
	    done = TRUE;
	}
    }
    /* If not an auth session, the authValue is never appended to the HMAC key or encrypt
       sessionValue, regardless of the binding */
    if (!done) {
	/* First, if there was a bind handle, check if the name matches.  Else bindMatch remains
	   FALSE. */
	if ((session->bind != TPM_RH_NULL) &&
	    /* a policy session acts as if the bind name does not match */
	    (session->sessionType != TPM_SE_POLICY)) {
	    /* get the handle for this session */
	    if (tssVverbose)
		printf("TSS_HmacSession_SetHmacKey: Processing bind handle %08x\n", session->bind);
	    if (rc == 0) {
		rc = TSS_GetCommandHandle(tssContext->tssAuthContext,
					  &commandHandle,
					  handleNumber);
	    }
	    /* get the Name corresponding to the handle */
	    if (rc == 0) {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: commandHandle %08x bindHandle %08x\n",
			   commandHandle, session->bind);
		rc = TSS_Name_GetName(tssContext, &name, commandHandle);
	    }
	    /* compare the authorized object name to the bind object name */
	    if (rc == 0) {
		bindMatch = TSS_TPM2B_Compare(&name.b, &session->bindName.b);
		if (tssVverbose) printf("TSS_HmacSession_SetHmacKey: bind match %u\n", bindMatch);
	    }
	}
	/* Second, append password to session key for HMAC key if required */
	if ((rc == 0) &&
	    !bindMatch &&		/* if bind matches, EmptyAuth appended.  */
	    (password != NULL) &&	/* if password is NULL, nothing to append. */
	    /* if policy session and no PolicyAuthValue, effectively not an auth session */
	    !((session->sessionType == TPM_SE_POLICY) && !session->isAuthValueNeeded)) {
	    
	    if (tssVverbose)
		printf("TSS_HmacSession_SetHmacKey: Appending authValue to HMAC key\n");
	    /* convert the password to an authvalue */
	    if (rc == 0) {
		rc = TSS_TPM2B_StringCopy(&authValue.b, password, sizeof(TPMU_HA));
	    }
	    /* append the authvalue to the session key to create the hmac key */
	    if (rc == 0) {
		rc = TSS_TPM2B_Append(&session->hmacKey.b, &authValue.b,
				      sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	}
	/* Third, append password to session key for sessionValue if required */
	/* NOTE This step occurs even if there is a bind match. That is, the password is effectively
	   appended twice. */
	if ((rc == 0) &&
	    !((session->sessionType == TPM_SE_POLICY) && !session->isAuthValueNeeded)) {

	    /* if not bind, sessionValue is sessionKey || authValue (same as HMAC key) */
	    if (!bindMatch) {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: "
			   "No bind, appending authValue to sessionValue\n");
		/* convert the password to an authvalue */
		if (rc == 0) {
		    rc = TSS_TPM2B_StringCopy(&authValue.b, password, sizeof(TPMU_HA));
		}
		if (rc == 0) {
		    rc = TSS_TPM2B_Append(&session->sessionValue.b, &authValue.b,
					  sizeof(TPMU_HA) + sizeof(TPMT_HA));
		}
	    }
	    /* if bind, session value is sessionKey || bindAuthValue */
	    else {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: "
			   "Bind, appending bind authValue to sessionValue\n");
		if (rc == 0) {
		    rc = TSS_TPM2B_Append(&session->sessionValue.b, &session->bindAuthValue.b,
					  sizeof(TPMU_HA) + sizeof(TPMT_HA));
		}
	    }
	    if (rc == 0) {
		if (tssVverbose)
		    TSS_PrintAll("TSS_HmacSession_SetHmacKey: bindAuthValue",
				 session->bindAuthValue.b.buffer, session->bindAuthValue.b.size);
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: hmacKey",
			 session->hmacKey.b.buffer, session->hmacKey.b.size);
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
    }
    return rc;
}
    
/* TSS_HmacSession_SetHMAC() is used for a command.  It sets all the values in one
   TPMS_AUTH_COMMAND, ready for marshaling into the command packet.

   - gets cpBuffer
   - generates cpHash
   - generates the HMAC
   - copies the result into authCommand

   Unused names must have size 0.

   The HMAC key is already in the session structure.
*/

static TPM_RC TSS_HmacSession_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization context */
				      struct TSS_HMAC_CONTEXT *session[],
				      TPMS_AUTH_COMMAND *authCommand[],	/* output: command
									   authorization */
				      TPMI_SH_AUTH_SESSION sessionHandle[], /* session handles in
									       command */
				      unsigned int sessionAttributes[],	/* attributes for this
									   command */
				      const char *password[],
				      TPM2B_NAME *name0,		/* up to 3 names */
				      TPM2B_NAME *name1,		/* unused names have length
									   0 */
				      TPM2B_NAME *name2)
{
    TPM_RC		rc = 0;
    unsigned int	i = 0;
    TPMT_HA 		cpHash;
    TPMT_HA 		hmac;
    TPM2B_NONCE	nonceTPMDecrypt;
    TPM2B_NONCE	nonceTPMEncrypt;

    cpHash.hashAlg = TPM_ALG_NULL;	/* for cpHash calculation optimzation */

    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	uint8_t sessionAttr8;
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: Step 6 session %08x\n", sessionHandle[i]);
	/* password sessions were serviced in step 2. */
	if (sessionHandle[i] == TPM_RS_PW) {
	    continue;
	}
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: sessionType %02x\n",
				session[i]->sessionType);
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: isPasswordNeeded %02x\n",
				session[i]->isPasswordNeeded);
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: isAuthValueNeeded %02x\n",
				session[i]->isAuthValueNeeded);
	/* sessionHandle */
	authCommand[i]->sessionHandle = session[i]->sessionHandle;
	/* attributes come from command */
	sessionAttr8 = (uint8_t)sessionAttributes[i];
	authCommand[i]->sessionAttributes.val = sessionAttr8;

	/* policy session with policy password handled below, no hmac.  isPasswordNeeded is never
	   true for an HMAC session, so don't need to test session type here. */
	if (!(session[i]->isPasswordNeeded)) {
	    /* HMAC session or policy session with TPM2_PolicyAuthValue needs HMAC */
	    if ((session[i]->sessionType == TPM_SE_HMAC) ||
		((session[i]->sessionType == TPM_SE_POLICY) && (session[i]->isAuthValueNeeded))) {
		    
		if (tssVverbose) printf("TSS_HmacSession_SetHMAC: calculate HMAC\n");
		/* calculate cpHash.  Performance optimization: If there is more than one session,
		   and the hash algorithm is the same, use the previously calculated version. */
		if ((rc == 0) && (cpHash.hashAlg != session[i]->authHashAlg)) {
		    uint32_t cpBufferSize;
		    uint8_t *cpBuffer;
		    TPM_CC commandCode;
		    TPM_CC commandCodeNbo;
	
		    rc = TSS_GetCpBuffer(tssAuthContext,
					 &cpBufferSize,
					 &cpBuffer);
		    if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetHMAC: cpBuffer",
						  cpBuffer, cpBufferSize);
		    cpHash.hashAlg = session[i]->authHashAlg;
    
		    // cpHash = hash(commandCode [ || authName1
		    //                           [ || authName2
		    //                           [ || authName 3 ]]]
		    //                           [ || parameters])
		    // A cpHash can contain just a commandCode only if the lone session is
		    // an audit session.

		    commandCode = TSS_GetCommandCode(tssAuthContext);
		    commandCodeNbo = htonl(commandCode);
		    rc = TSS_Hash_Generate(&cpHash,		/* largest size of a digest */
					   sizeof(TPM_CC), &commandCodeNbo,
					   name0->b.size, &name0->b.buffer,
					   name1->b.size, &name1->b.buffer,
					   name2->b.size, &name2->b.buffer,
					   cpBufferSize, cpBuffer,
					   0, NULL);
		}
		if (i == 0) {
		    unsigned int 	isDecrypt = 0;	/* count number of sessions with decrypt
							   set */
		    unsigned int	decryptSession = 0;	/* which one is decrypt */
		    unsigned int 	isEncrypt = 0;	/* count number of sessions with decrypt
							   set */
		    unsigned int	encryptSession = 0;	/* which one is decrypt */
		    nonceTPMDecrypt.t.size = 0;
		    nonceTPMEncrypt.t.size = 0;
		    /* if a different session is being used for parameter decryption, then the
		       nonceTPM for that session is included in the HMAC of the first authorization
		       session */
		    if (rc == 0) {
			rc = TSS_Sessions_GetDecryptSession(&isDecrypt,
							    &decryptSession,
							    sessionHandle,
							    sessionAttributes);
		    }
		    if ((rc == 0) && isDecrypt && (decryptSession != 0)) {
			rc = TSS_TPM2B_Copy(&nonceTPMDecrypt.b,
					    &session[decryptSession]->nonceTPM.b, sizeof(TPMU_HA));
		    }
		    /* if a different session is being used for parameter encryption, then the
		       nonceTPM for that session is included in the HMAC of the first authorization
		       session */
		    if (rc == 0) {
			rc = TSS_Sessions_GetEncryptSession(&isEncrypt,
							    &encryptSession,
							    sessionHandle,
							    sessionAttributes);
		    }
		    /* Don't include the same nonce twice */
		    if ((rc == 0) && isEncrypt && (encryptSession != 0)) {
			if (!isDecrypt || (encryptSession != decryptSession)) {
			    rc = TSS_TPM2B_Copy(&nonceTPMEncrypt.b, 
						&session[encryptSession]->nonceTPM.b, sizeof(TPMU_HA));
			}
		    }
		}
		/* for other than the first session, those nonces are not used */
		else {
		    nonceTPMDecrypt.t.size = 0;
		    nonceTPMEncrypt.t.size = 0;
		}
		/* */
		if (rc == 0) {
		    hmac.hashAlg = session[i]->authHashAlg;
		    rc = TSS_HMAC_Generate(&hmac,				/* output hmac */
					   &session[i]->hmacKey,		/* input key */
					   session[i]->sizeInBytes, (uint8_t *)&cpHash.digest,
					   /* new is nonceCaller */
					   session[i]->nonceCaller.b.size,
					   &session[i]->nonceCaller.b.buffer,
					   /* old is previous nonceTPM */
					   session[i]->nonceTPM.b.size,
					   &session[i]->nonceTPM.b.buffer,
					   /* nonceTPMDecrypt */
					   nonceTPMDecrypt.b.size, nonceTPMDecrypt.b.buffer,
					   /* nonceTPMEncrypt */
					   nonceTPMEncrypt.b.size, nonceTPMEncrypt.b.buffer,
					   /* 1 byte, no endian conversion */
					   sizeof(uint8_t), &sessionAttr8,
					   0, NULL);
		    if (tssVverbose) {
			TSS_PrintAll("TSS_HmacSession_Set: HMAC key",
				     session[i]->hmacKey.t.buffer, session[i]->hmacKey.t.size);
			TSS_PrintAll("TSS_HmacSession_Set: cpHash",
				     (uint8_t *)&cpHash.digest, session[i]->sizeInBytes);
			TSS_PrintAll("TSS_HmacSession_Set: nonceCaller",
				     session[i]->nonceCaller.b.buffer,
				     session[i]->nonceCaller.b.size);
			TSS_PrintAll("TSS_HmacSession_Set: nonceTPM",
				     session[i]->nonceTPM.b.buffer, session[i]->nonceTPM.b.size);
			TSS_PrintAll("TSS_HmacSession_Set: nonceTPMDecrypt",
				     nonceTPMDecrypt.b.buffer, nonceTPMDecrypt.b.size);
			TSS_PrintAll("TSS_HmacSession_Set: nonceTPMEncrypt",
				     nonceTPMEncrypt.b.buffer, nonceTPMEncrypt.b.size);
			TSS_PrintAll("TSS_HmacSession_Set: sessionAttributes",
				     &sessionAttr8, sizeof(uint8_t));
			TSS_PrintAll("TSS_HmacSession_Set: HMAC",
				     (uint8_t *)&hmac.digest, session[i]->sizeInBytes);
		    }
		}
		/* copy HMAC into authCommand TPM2B_AUTH hmac */
		if (rc == 0) {
		    rc = TSS_TPM2B_Create(&authCommand[i]->hmac.b,
					  (uint8_t *)&hmac.digest,
					  session[i]->sizeInBytes, sizeof(TPMU_HA));
		}
	    }
	    /* not HMAC, not policy requiring password or hmac */
	    else {
		authCommand[i]->hmac.b.size = 0;
	    }
	}
	/* For a policy session that contains TPM2_PolicyPassword(), the password takes precedence
	   and must be present in hmac. */
 	else {
	    if (tssVverbose) printf("TSS_HmacSession_SetHMAC: use password\n");
	    /* nonce has already been set */
	    rc = TSS_TPM2B_StringCopy(&authCommand[i]->hmac.b, password[i], sizeof(TPMU_HA));
	}
    }
    return rc;
}

/* TSS_HmacSession_Verify() is used for a response.  It uses the values in TPMS_AUTH_RESPONSE to
   validate the response HMAC
*/

TPM_RC TSS_HmacSession_Verify(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization context */
			      struct TSS_HMAC_CONTEXT *session,	/* TSS session context */
			      TPMS_AUTH_RESPONSE *authResponse)	/* input: response authorization */
{
    TPM_RC		rc = 0;
    uint32_t		rpBufferSize;
    uint8_t 		*rpBuffer;
    TPMT_HA 		rpHash;
    TPMT_HA 		actualHmac;

    /* get the rpBuffer */
    if (rc == 0) {
	rc = TSS_GetRpBuffer(tssAuthContext, &rpBufferSize, &rpBuffer);
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession_Verify: rpBuffer",
				      rpBuffer, rpBufferSize);
    }
    /* calculate rpHash */
    if (rc == 0) {
	TPM_CC commandCode;
	TPM_CC commandCodeNbo;
	rpHash.hashAlg = session->authHashAlg;
	
	commandCode = TSS_GetCommandCode(tssAuthContext);
	commandCodeNbo = htonl(commandCode);
	
	/* rpHash = HsessionAlg (responseCode || commandCode {|| parameters })	 */
	rc = TSS_Hash_Generate(&rpHash,			/* largest size of a digest */
			       sizeof(TPM_RC), &rc,	/* RC is always 0, no need to endian
							   convert */
			       sizeof(TPM_CC), &commandCodeNbo,
			       rpBufferSize, rpBuffer,
			       0, NULL);
    }
    /* construct the actual HMAC as TPMT_HA */
    if (rc == 0) {
	actualHmac.hashAlg = session->authHashAlg;
	if (authResponse->hmac.t.size != session->sizeInBytes) {
	    if (tssVerbose)
		printf("TSS_HmacSession_Verify: HMAC size %u inconsistent with algorithm %u\n",
		       authResponse->hmac.t.size, session->sizeInBytes);
	    rc = TSS_RC_HMAC_SIZE;
	}
    }
    if (rc == 0) {
	memcpy((uint8_t *)&actualHmac.digest, &authResponse->hmac.t.buffer,
	       authResponse->hmac.t.size);
    }
    /* verify the HMAC */
    if (rc == 0) {
	if (tssVverbose) {
	    TSS_PrintAll("TSS_HmacSession_Verify: HMAC key",
			 session->hmacKey.t.buffer, session->hmacKey.t.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: rpHash",
			 (uint8_t *)&rpHash.digest, session->sizeInBytes);
	    TSS_PrintAll("TSS_HmacSession_Verify: nonceTPM",
			 session->nonceTPM.b.buffer, session->nonceTPM.b.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: nonceCaller",
			 session->nonceCaller.b.buffer, session->nonceCaller.b.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: sessionAttributes",
			 &authResponse->sessionAttributes.val, sizeof(uint8_t));
	    TSS_PrintAll("TSS_HmacSession_Verify: response HMAC",
			 (uint8_t *)&authResponse->hmac.t.buffer, session->sizeInBytes);
	}
	rc = TSS_HMAC_Verify(&actualHmac,		/* input response hmac */
			     &session->hmacKey,		/* input HMAC key */
			     session->sizeInBytes,
			     /* rpHash */
			     session->sizeInBytes, (uint8_t *)&rpHash.digest,
			     /* new is nonceTPM */
			     session->nonceTPM.b.size, &session->nonceTPM.b.buffer,
			     /* old is nonceCaller */
			     session->nonceCaller.b.size, &session->nonceCaller.b.buffer,
			     /* 1 byte, no endian conversion */
			     sizeof(uint8_t), &authResponse->sessionAttributes.val,
			     0, NULL);
    }
    return rc;
}

/* TSS_HmacSession_Continue() handles the response continueSession flag.  It either saves the
   updated session or deletes the session state. */

static TPM_RC TSS_HmacSession_Continue(TSS_CONTEXT *tssContext,
				       struct TSS_HMAC_CONTEXT *session,
				       TPMS_AUTH_RESPONSE *authR)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	/* if continue set */
	if (authR->sessionAttributes.val & TPMA_SESSION_CONTINUESESSION) {
	    /* clear the policy flags in preparation for the next use */
	    session->isPasswordNeeded = FALSE;
	    session->isAuthValueNeeded = FALSE;
	    /* save the session */
	    rc = TSS_HmacSession_SaveSession(tssContext, session);
	}
	else {		/* continue clear */
	    /* delete the session state */
	    rc = TSS_DeleteHandle(tssContext, session->sessionHandle);
	}
    }
    return rc;
}

static TPM_RC TSS_Sessions_GetDecryptSession(unsigned int *isDecrypt,
					     unsigned int *decryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	i = 0;

    /* count the number of command decrypt sessions */
    *isDecrypt = 0;		/* number of sessions with decrypt set */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionAttributes[i] & TPMA_SESSION_DECRYPT) {
	    (*isDecrypt)++;		/* count number of decrypt sessions */
	    *decryptSession = i;	/* record which one it was */
	}
    }
    /* how many decrypt sessions were found */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Sessions_GetDecryptSession: Found %u decrypt sessions\n",
				*isDecrypt);
	if (*isDecrypt > 1) {
	    if (tssVerbose)
		printf("TSS_Sessions_GetDecryptSession: Error, found %u decrypt sessions\n",
		       *isDecrypt);
	    rc = TSS_RC_DECRYPT_SESSIONS;
	}
    }
    return rc;
}

static TPM_RC TSS_Sessions_GetEncryptSession(unsigned int *isEncrypt,
					     unsigned int *encryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	i = 0;

    /* count the number of command encrypt sessions */
    *isEncrypt = 0;		/* number of sessions with encrypt set */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionAttributes[i] & TPMA_SESSION_ENCRYPT) {
	    (*isEncrypt)++;		/* count number of encrypt sessions */
	    *encryptSession = i;	/* record which one it was */
	}
    }
    /* how many encrypt sessions were found */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Sessions_GetEncryptSession: Found %u encrypt sessions\n",
				*isEncrypt);
	if (*isEncrypt > 1) {
	    if (tssVerbose)
		printf("TSS_Sessions_GetEncryptSession: Error, found %u encrypt sessions\n",
		       *isEncrypt);
	    rc = TSS_RC_ENCRYPT_SESSIONS;
	}
    }
    return rc;
}


/* TSS_Command_Decrypt() determines whether any sessions are command decrypt sessions.  If so,
   it encrypts the first command parameter.

   It does common error chacking, then calls algorithm specific functions.
*/

static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  struct TSS_HMAC_CONTEXT *session[],
				  TPMI_SH_AUTH_SESSION sessionHandle[],
				  unsigned int	sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	isDecrypt = 0;		/* count number of sessions with decrypt set */
    unsigned int	decryptSession = 0;	/* which one is decrypt */
    COMMAND_INDEX    	tpmCommandIndex;	/* index into TPM table */
    TPM_CC 		commandCode;
    int			decryptSize;		/* size of TPM2B size, 2 if there is a TPM2B, 0 if
						   not */
    uint32_t 		paramSize;		/* size of the parameter to encrypt */	
    uint8_t 		*decryptParamBuffer;

    if (rc == 0) {
	rc = TSS_Sessions_GetDecryptSession(&isDecrypt,
					    &decryptSession,
					    sessionHandle,
					    sessionAttributes);
    }
    /* can the command parameter be encrypted */
    if ((rc == 0) && isDecrypt) {
	/* get the commandCode, stored in TSS during marshal */
	commandCode  = TSS_GetCommandCode(tssAuthContext);
	/* get the index into the TPM command attributes table */
	tpmCommandIndex = CommandCodeToCommandIndex(commandCode);
	/* can this be a decrypt command (this is size of TPM2B size, not size of parameter) */
	decryptSize = getDecryptSize(tpmCommandIndex);
	if (decryptSize != 2) {		/* only handle TPM2B */
	    printf("TSS_Command_Decrypt: Error, command cannot be encrypted\n");
	    rc = TSS_RC_NO_DECRYPT_PARAMETER;
	}
    }
    /* get the TPM2B parameter to encrypt */
    if ((rc == 0) && isDecrypt) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
    }
    /* if the size of the parameter to encrypt is zero, nothing to encrypt */
    if ((rc == 0) && isDecrypt) {
	if (paramSize == 0) {
	    isDecrypt = FALSE;	/* none, done with this function */
	}
    }
    /* error checking complete, do the encryption */
    if ((rc == 0) && isDecrypt) {
	switch (session[decryptSession]->symmetric.algorithm) {
	  case TPM_ALG_XOR:
	    rc = TSS_Command_DecryptXor(tssAuthContext, session[decryptSession]);
	    break;
	  case TPM_ALG_AES:
	    rc = TSS_Command_DecryptAes(tssAuthContext, session[decryptSession]);
	    break;
	  default:
	    if (tssVerbose) printf("TSS_Command_Decrypt: Error, algorithm %04x not implemented\n",
				   session[decryptSession]->symmetric.algorithm);
	    rc = TSS_RC_BAD_DECRYPT_ALGORITHM;
	    break;
	}
    }
    return rc;
}

/* NOTE: if AES also works, do in place encryption */

static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    unsigned int	i;
    uint32_t 		paramSize;
    uint8_t 		*decryptParamBuffer;
    uint8_t 		*mask = NULL;
    uint8_t 		*encryptParamBuffer = NULL;
    uint16_t		maskSize;

    /* get the TPM2B parameter to encrypt */
    if (rc == 0) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: decrypt in",
				      decryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	mask = malloc(paramSize);
	if (mask == NULL) {
	    if (tssVerbose) printf("TSS_Command_DecryptXor: malloc %u failed\n",
				   (unsigned int)sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	encryptParamBuffer = malloc(paramSize);
	if (mask == NULL) {
	    if (tssVerbose) printf("TSS_Command_DecryptXor: malloc %u failed\n",
				   (unsigned int)sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* generate the XOR pad */
    /* 21.2	XOR Parameter Obfuscation

       XOR(parameter, hashAlg, sessionValue, nonceNewer, nonceOlder)

       parameter	a variable sized buffer containing the parameter to be obfuscated
       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       nonceNewer	for commands, this will be nonceCaller and for responses it will be nonceTPM
       nonceOlder	for commands, this will be nonceTPM and for responses it will be nonceCaller

       11.4.6.3	XOR Obfuscation

       XOR(data, hashAlg, key, contextU, contextV)
       
       mask = KDFa (hashAlg, key, "XOR", contextU, contextV, data.size * 8)
    */
    /* KDFa for the XOR mask */
    if (rc == 0) {
	uint32_t	counterInOut = 0;
	if (tssVverbose) printf("TSS_Command_DecryptXor: hashAlg %04x\n", session->authHashAlg);
	if (tssVverbose) printf("TSS_Command_DecryptXor: sizeInBits %04x\n", paramSize * 8);
	if (tssVverbose)
	    TSS_PrintAll("TSS_Command_DecryptXor: sessionKey",
			 session->sessionKey.b.buffer, session->sessionKey.b.size);
	if (tssVverbose)
	    TSS_PrintAll("TSS_Command_DecryptXor: sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
	maskSize = _cpri__KDFa(session->authHashAlg,
			       &session->sessionValue.b,
			       "XOR",
			       &session->nonceCaller.b,
			       &session->nonceTPM.b,
			       paramSize * 8,
			       mask,
			       &counterInOut,
			       FALSE);
	if (maskSize == 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptXor: KDFa failed\n");
	    rc = TSS_RC_KDFA_FAILED;
	}
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: mask",
				      mask, paramSize);
    }
    /* XOR */
    for (i = 0 ; (rc == 0) && (i < paramSize ) ; i++)  {
	encryptParamBuffer[i] = decryptParamBuffer[i] ^ mask[i];
    }
    if (rc == 0) {
	rc = TSS_SetCommandDecryptParam(tssAuthContext, paramSize, encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: encrypt out",
				      encryptParamBuffer, paramSize);
    }
    free(mask);
    free(encryptParamBuffer);
    return rc;
}

/* NOTE: if AES also works, do in place encryption */

static TPM_RC TSS_Command_DecryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    uint32_t 		paramSize;
    uint8_t 		*decryptParamBuffer;
    uint8_t 		*encryptParamBuffer = NULL;
    TPM2B_IV		iv;
    uint32_t           	kdfaBits;
    uint16_t		kdfRc;
    uint16_t		keySizeinBytes;
    uint8_t		symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];	/* AES key + IV */
    
    /* get the TPM2B parameter to encrypt */
    if (rc == 0) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: decrypt in",
				      decryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	encryptParamBuffer = malloc(paramSize);
	if (encryptParamBuffer == NULL) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: malloc %u failed\n",
				   (unsigned int)sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* generate the encryption key and IV */
    /* 21.3	CFB Mode Parameter Encryption

       KDFa (hashAlg, sessionValue, "CFB", nonceNewer, nonceOlder, bits)	(34)

       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       "CFB"		label to differentiate use of KDFa() (see 4.2)
       nonceNewer	nonceCaller for a command and nonceTPM for a response
       nonceOlder	nonceTPM for a command and nonceCaller for a response
       bits		the number of bits required for the symmetric key plus an IV
    */
    if (rc == 0) {
	uint32_t	counterInOut = 0;
	
	iv.t.size = _cpri__GetSymmetricBlockSize(session->symmetric.algorithm,
						 session->symmetric.keyBits.aes);
	/* generate random values for both the AES key and the IV */
	kdfaBits = session->symmetric.keyBits.aes + (iv.t.size * 8);

	if (tssVverbose) printf("TSS_Command_DecryptAes: hashAlg %04x\n",
				session->authHashAlg);
	if (tssVverbose) printf("TSS_Command_DecryptAes: AES key bits %u\n",
				session->symmetric.keyBits.aes);
	if (tssVverbose) printf("TSS_Command_DecryptAes: kdfaBits %04x\n",
				kdfaBits);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);

	kdfRc = _cpri__KDFa(session->authHashAlg,
			    &session->sessionValue.b,
			    "CFB",
			    &session->nonceCaller.b,
			    &session->nonceTPM.b,
			    kdfaBits,
			    &symParmString[0],
			    &counterInOut,
			    FALSE);
	if (kdfRc == 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: KDFa failed\n");
	    rc = TSS_RC_KDFA_FAILED;
	}
    }
    /* copy the latter part of the kdf output to the IV */
    if (rc == 0) {
	keySizeinBytes = session->symmetric.keyBits.aes / 8;
	memcpy(iv.t.buffer, &symParmString[keySizeinBytes], iv.t.size);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: IV",
				      iv.t.buffer, iv.t.size);
    }
    /* AES CFB encrypt the command */
    if (rc == 0) {
	CRYPT_RESULT	crc;
	crc = _cpri__AESEncryptCFB(encryptParamBuffer,	/* output */
				   128,			/* FIXME session->symmetric.keyBits.aes */
				   symParmString,	/* key */
				   iv.t.buffer,		/* IV */
				   paramSize,		/* length */
				   (uint8_t *)decryptParamBuffer);	/* input */
	if (crc != 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: AES encrypt failed\n");
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }		 
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: encrypt out",
				      encryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetCommandDecryptParam(tssAuthContext, paramSize, encryptParamBuffer);
    }
    free(encryptParamBuffer);
    return rc;
}    

static TPM_RC TSS_Response_Encrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				   struct TSS_HMAC_CONTEXT *session[],
				   TPMI_SH_AUTH_SESSION sessionHandle[],
				   unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	isEncrypt = 0;		/* count number of sessions with decrypt set */
    unsigned int	encryptSession = 0;	/* which one is decrypt */
    COMMAND_INDEX    	tpmCommandIndex;	/* index into TPM table */
    TPM_CC 		commandCode;
    int			encryptSize;		/* size of TPM2B size, 2 if there is a TPM2B, 0 if
						   not */
    uint32_t 		paramSize;		/* size of the parameter to decrypt */	
    uint8_t 		*encryptParamBuffer;
    
    if (rc == 0) {
	rc = TSS_Sessions_GetEncryptSession(&isEncrypt,
					    &encryptSession,
					    sessionHandle,
					    sessionAttributes);
    }
    /* can the response parameter be decrypted */
    if ((rc == 0) && isEncrypt) {
	/* get the commandCode, stored in TSS during marshal */
	commandCode  = TSS_GetCommandCode(tssAuthContext);
	/* get the index into the TPM command attributes table */
	tpmCommandIndex = CommandCodeToCommandIndex(commandCode);
	/* can this be a decrypt command */
	encryptSize = getEncryptSize(tpmCommandIndex);
	if (encryptSize == 0) {
	    if (tssVerbose) printf("TSS_Response_Encrypt: Error, response cannot be encrypted\n");
	    rc = TSS_RC_NO_ENCRYPT_PARAMETER;
	}
    }
    /* get the TPM2B parameter to decrypt */
    if ((rc == 0) && isEncrypt) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext, &paramSize, &encryptParamBuffer);
    }
    /* if the size of the parameter to decrypt is zero, nothing to decrypt */
    if ((rc == 0) && isEncrypt) {
	if (paramSize == 0) {
	    isEncrypt = FALSE;	/* none, done with this function */
	}
    }
    /* error checking complete, do the decryption */
    if ((rc == 0) && isEncrypt) {
	switch (session[encryptSession]->symmetric.algorithm) {
	  case TPM_ALG_XOR:
	    rc = TSS_Response_EncryptXor(tssAuthContext, session[encryptSession]);
	    break;
	  case TPM_ALG_AES:
	    rc = TSS_Response_EncryptAes(tssAuthContext, session[encryptSession]);
	    break;
	  default:
	    if (tssVerbose) printf("TSS_Response_Encrypt: Error, algorithm %04x not implemented\n",
				   session[encryptSession]->symmetric.algorithm);
	    rc = TSS_RC_BAD_ENCRYPT_ALGORITHM;
	    break;
	}
    }
    return rc;
}
/* NOTE: if CFB also works, do in place decryption */

static TPM_RC TSS_Response_EncryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    unsigned int	i;
    uint32_t 		paramSize;
    uint8_t 		*encryptParamBuffer;
    uint8_t 		*mask = NULL;
    uint8_t 		*decryptParamBuffer = NULL;
    uint16_t		maskSize;

    /* get the TPM2B parameter to decrypt */
    if (rc == 0) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext,
					 &paramSize, &encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: encrypt in",
				      encryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	mask = malloc(paramSize);
	if (mask == NULL) {
	    if (tssVerbose) printf("TSS_Response_EncryptXor: malloc %u failed\n",
				   (unsigned int)sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	decryptParamBuffer = malloc(paramSize);
	if (mask == NULL) {
	    if (tssVerbose) printf("TSS_Response_EncryptXor: malloc %u failed\n",
				   (unsigned int)sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* generate the XOR pad */
    /* 21.2	XOR Parameter Obfuscation

       XOR(parameter, hashAlg, sessionValue, nonceNewer, nonceOlder)

       parameter	a variable sized buffer containing the parameter to be obfuscated
       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       nonceNewer	for commands, this will be nonceCaller and for responses it will be nonceTPM
       nonceOlder	for commands, this will be nonceTPM and for responses it will be nonceCaller

       
       11.4.6.3	XOR Obfuscation

       XOR(data, hashAlg, key, contextU, contextV)
       
       mask = KDFa (hashAlg, key, "XOR", contextU, contextV, data.size * 8)
    */
    /* KDFa for the XOR mask */
    if (rc == 0) {
	uint32_t	counterInOut = 0;
	if (tssVverbose) printf("TSS_Response_EncryptXor: hashAlg %04x\n", session->authHashAlg);
	if (tssVverbose) printf("TSS_Response_EncryptXor: sizeInBits %04x\n", paramSize * 8);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	maskSize = _cpri__KDFa(session->authHashAlg,
			       &session->sessionValue.b,
			       "XOR",
			       &session->nonceTPM.b,
			       &session->nonceCaller.b,
			       paramSize * 8,
			       mask,
			       &counterInOut,
			       FALSE);
	if (maskSize == 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptXor: KDFa failed\n");
	    rc = TSS_RC_KDFA_FAILED;
	}
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: mask",
				      mask, paramSize);
    }
    /* XOR */
    for (i = 0 ; (rc == 0) && (i < paramSize ) ; i++)  {
	decryptParamBuffer[i] = encryptParamBuffer[i] ^ mask[i];
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: decrypt out",
				      decryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetResponseDecryptParam(tssAuthContext,
					 paramSize, decryptParamBuffer);
    }
    free(mask);
    free(decryptParamBuffer);
    return rc;
}

/* NOTE: if CFB also works, do in place decryption */


static TPM_RC TSS_Response_EncryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    uint32_t 		paramSize;
    uint8_t 		*encryptParamBuffer;
    uint8_t 		*decryptParamBuffer = NULL;
    TPM2B_IV		iv;
    uint32_t           	kdfaBits;
    uint16_t		kdfRc;
    uint16_t		keySizeinBytes;
    uint8_t		symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];	/* AES key + IV */

    /* get the TPM2B parameter to decrypt */
    if (rc == 0) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext,
					 &paramSize, &encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: encrypt in",
				      encryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	decryptParamBuffer = malloc(paramSize);
	if (decryptParamBuffer == NULL) {
	    if (tssVerbose) printf("TSS_Response_EncryptAes: malloc %u failed\n",
				   (unsigned int)	sizeof(paramSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* generate the encryption key and IV */
    /* 21.3	CFB Mode Parameter Encryption

       KDFa (hashAlg, sessionValue, "CFB", nonceNewer, nonceOlder, bits)	(34)
    */
    if (rc == 0) {
	uint32_t	counterInOut = 0;
	
	iv.t.size = _cpri__GetSymmetricBlockSize(session->symmetric.algorithm,
						 session->symmetric.keyBits.aes);
	/* generate random values for both the AES key and the IV */
	kdfaBits = session->symmetric.keyBits.aes + (iv.t.size * 8);

	if (tssVverbose) printf("TSS_Response_EncryptAes: hashAlg %04x\n",
				session->authHashAlg);
	if (tssVverbose) printf("TSS_Response_EncryptAes: AES key bits %u\n",
				session->symmetric.keyBits.aes);
	if (tssVverbose) printf("TSS_Response_EncryptAes: kdfaBits %04x\n",
				kdfaBits);
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	
	kdfRc = _cpri__KDFa(session->authHashAlg,
			    &session->sessionValue.b,
			    "CFB",
			    &session->nonceTPM.b,
			    &session->nonceCaller.b,
			    kdfaBits,
			    &symParmString[0],
			    &counterInOut,
			    FALSE);
	if (kdfRc == 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: KDFa failed\n");
	    rc = TSS_RC_KDFA_FAILED;
	}
    }
    /* copy the latter part of the kdf output to the IV */
    if (rc == 0) {
	keySizeinBytes = session->symmetric.keyBits.aes / 8;
	memcpy(iv.t.buffer, &symParmString[keySizeinBytes], iv.t.size);
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: IV",
				      iv.t.buffer, iv.t.size);
    }
    /* AES CFB decrypt the response */
    if (rc == 0) {
	CRYPT_RESULT	crc;
	crc = _cpri__AESDecryptCFB(decryptParamBuffer,	/* output */
				   128,			/* FIXME session->symmetric.keyBits.aes */
				   symParmString,	/* key */
				   iv.t.buffer,		/* IV */
				   paramSize,		/* length */
				   (uint8_t *)encryptParamBuffer);	/* input */
	if (crc != 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: AES decrypt failed\n");
	    rc = TSS_RC_AES_DECRYPT_FAILURE;
	}
    }		 
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: decrypt out",
				      decryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetResponseDecryptParam(tssAuthContext,
					 paramSize, decryptParamBuffer);
    }
    free(decryptParamBuffer);
    return rc;
}

/*
  Command Change Authorization Processor
*/

static TPM_RC TSS_Command_ChangeAuthProcessor(TSS_CONTEXT *tssContext,
					      struct TSS_HMAC_CONTEXT *session,
					      size_t handleNumber,
					      COMMAND_PARAMETERS *in)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_ChangeAuthFunction_t 	changeAuthFunction = NULL;

    TPM_CC commandCode = TSS_GetCommandCode(tssContext->tssAuthContext);

    /* search the table for a change authorization processing function */
    if (rc == 0) {
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no change authorization function.  This permits the table to be
       smaller if desired. */
    if ((rc == 0) && found) {
	changeAuthFunction = tssTable[index].changeAuthFunction;
	/* there could also be an entry that it currently NULL, nothing to do */
	if (changeAuthFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the processing function */
    if ((rc == 0) && found) {
	rc = changeAuthFunction(tssContext, session, handleNumber, in);
    }
    return rc;
}

static TPM_RC TSS_CA_HierarchyChangeAuth(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 HierarchyChangeAuth_In *in)
{
    TPM_RC 		rc = 0;
    char		*password = NULL;
    
    if (tssVverbose) printf("TSS_CA_HierarchyChangeAuth\n");
    if (in->newAuth.t.size == 0) {
	password = NULL;
    }
    else {
	if (rc == 0) {
	    password = malloc(in->newAuth.t.size + 1);
	    if (password == NULL) {
		if (tssVerbose) printf("TSS_CA_HierarchyChangeAuth: malloc %u failed\n",
				       in->newAuth.t.size + 1);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    /* copy the password */
	    memcpy(password, in->newAuth.t.buffer, in->newAuth.t.size);
	    password[in->newAuth.t.size] = '\0';	/* nul terminate string */
	}
    }
    if (rc == 0) {
	rc = TSS_HmacSession_SetHmacKey(tssContext,
					session,
					handleNumber,
					password);
    }
    free(password);
    return rc;
}

static TPM_RC TSS_CA_NV_ChangeAuth(TSS_CONTEXT *tssContext,
				   struct TSS_HMAC_CONTEXT *session,
				   size_t handleNumber,
				   NV_ChangeAuth_In *in)
{
    TPM_RC 		rc = 0;
    char		*password = NULL;

    if (tssVverbose) printf("TSS_CA_NV_ChangeAuth\n");
    if (in->newAuth.t.size == 0) {
	password = NULL;
    }
    else {
	if (rc == 0) {
	    password = malloc(in->newAuth.t.size + 1);
	    if (password == NULL) {
		if (tssVerbose) printf("TSS_CA_NV_ChangeAuth: malloc %u failed\n",
				       in->newAuth.t.size + 1);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    /* copy the password */
	    memcpy(password, in->newAuth.t.buffer, in->newAuth.t.size);
	    password[in->newAuth.t.size] = '\0';	/* nul terminate string */
	}
    }
    if (rc == 0) {
	rc = TSS_HmacSession_SetHmacKey(tssContext,
					session,
					handleNumber,
					password);
    }
    free(password);
    return rc;
}

static TPM_RC TSS_CA_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     struct TSS_HMAC_CONTEXT *session,
					     size_t handleNumber,
					     NV_UndefineSpaceSpecial_In *in)
{
    TPM_RC 		rc = 0;
    
    in = in;
    if (tssVverbose) printf("TSS_CA_NV_UndefineSpaceSpecial\n");
    if (rc == 0) {
	/* the nvIndex authorization, the zeroth authorization, has special handling */
	if (handleNumber == 0) {
	    /* the Empty Buffer is used as the authValue when generating the response HMAC */
	    rc = TSS_HmacSession_SetHmacKey(tssContext,
					    session,
					    handleNumber,
					    NULL);		/* password */
	}
    }
    return rc;
}

/*
  Command Pre-Processor
*/

static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA_PARAMETERS *extra)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_PreProcessFunction_t 	preProcessFunction = NULL;

    /* search the table for a pre-processing function */
    if (rc == 0) {
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no pre-processing function.  This permits the table to be smaller
       if desired. */
    if ((rc == 0) && found) {
	preProcessFunction = tssTable[index].preProcessFunction;
	/* there could also be an entry that is currently NULL, nothing to do */
	if (preProcessFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the pre processing function */
    if ((rc == 0) && found) {
	rc = preProcessFunction(tssContext, in, extra);
    }
    return rc;
}

/*
  Command specific pre processing functions
*/

/* TSS_PR_StartAuthSession handles StartAuthSession pre processing.

   If the salt key in->tpmKey is not NULL and an RSA key, the preprocessor supplies the encrypted
   salt.  It passes the unencrypted salt to the post processor for session key processing.

   An input salt (encrypted or unencrypted) is ignored.

   Returns an error if the key is not an RSA key.
*/

static TPM_RC TSS_PR_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Extra *extra)
{
    TPM_RC 			rc = 0;
    TPM2B_PUBLIC		bPublic;
    TPMT_PUBLIC			*publicArea;	/* the public area  */
    
    if (tssVverbose) printf("TSS_PR_StartAuthSession\n");
    /* generate nonceCaller */
    if (rc == 0) {
	/* the size is determined by the session hash algorithm */
	in->nonceCaller.t.size = TSS_GetDigestSize(in->authHash);
	if (in->nonceCaller.t.size == 0) {
	    if (tssVerbose) printf("TSS_PR_StartAuthSession: hash algorithm %04x not implemented\n",
				   in->authHash);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    if (rc == 0) {
	rc = TSS_RandBytes((unsigned char *)&in->nonceCaller.t.buffer, in->nonceCaller.t.size);
    }
    /* initialize to handle unsalted session */
    in->encryptedSalt.t.size = 0;
    if (extra != NULL) {		/* extra NULL is handled at the port processor */
	extra->salt.t.size = 0;
    }
    /* if the caller requests a salted session */
    if (in->tpmKey != TPM_RH_NULL) {
	if (rc == 0) {
	    if (extra == NULL) {
		if (tssVerbose)
		    printf("TSS_PR_StartAuthSession: salt session requires extra parameter\n");
		rc = TSS_RC_NULL_PARAMETER;
	    }
	}
	/* get the tpmKey public key */
	if (rc == 0) {
	    rc = TSS_Public_Load(tssContext, &bPublic, in->tpmKey, NULL);
	}
	/* check the public key parameters for suitability */
	if (rc == 0) {
	    /* bPublic = &rpOut.outPublic; */
	    publicArea = &bPublic.t.publicArea;
	    {
		/* error conditions when true */
		int b1 = publicArea->type != TPM_ALG_RSA;
		int b2 = publicArea->objectAttributes.val & TPMA_OBJECT_SIGN;
		int b3 = !(publicArea->objectAttributes.val & TPMA_OBJECT_DECRYPT);
		int b4 = publicArea->parameters.rsaDetail.keyBits != 2048;
		int b5 = publicArea->parameters.rsaDetail.exponent != 0;
		/* TSS support checks */
		if (b1 || b2 || b3 || b4 || b5) {
		    if (tssVerbose)
			printf("TSS_PR_StartAuthSession: public key attributes not supported\n");
		    rc = TSS_RC_BAD_SALT_KEY;
		}
	    }
	}    
	if (rc == 0) {
	    if (tssVverbose) TSS_PrintAll("TSS_PR_StartAuthSession: public key",
					  publicArea->unique.rsa.t.buffer,
					  publicArea->unique.rsa.t.size);
	}
	/* generate a salt */
	if (rc == 0) {
	    /* The size of the secret value is limited to the size of the digest produced by the
	       nameAlg of the object that is associated with the public key used for OAEP
	       encryption. */
	    extra->salt.t.size = TSS_GetDigestSize(publicArea->nameAlg);
	    if (tssVverbose) printf("TSS_PR_StartAuthSession: Hash algorithm %04x Salt size %u\n",
				    publicArea->nameAlg, extra->salt.t.size);
	    /* place the salt in extra so that it can be retrieved by post processor */
	    rc = TSS_RandBytes((uint8_t *)&extra->salt.t.buffer, extra->salt.t.size);
	}
	/* In TPM2_StartAuthSession(), when tpmKey is an RSA key, the secret value (salt) is
	   encrypted using OAEP as described in B.4. The string "SECRET" (see 4.5) is used as the L
	   value and the nameAlg of the encrypting key is used for the hash algorithm. The data
	   value in OAEP-encrypted blob (salt) is used to compute sessionKey. */
	if (rc == 0) {
	    if (tssVverbose) TSS_PrintAll("TSS_PR_StartAuthSession: salt",
					  (uint8_t *)&extra->salt.t.buffer,
					  extra->salt.t.size);
	}
	/* encrypt the salt */
	if (rc == 0) {
	    /* public exponent */
	    unsigned char earr[3] = {0x01, 0x00, 0x01};
	    /* encrypt the salt with the tpmKey public key */
	    rc = TSS_RSAPublicEncrypt((uint8_t *)&in->encryptedSalt.t.secret,   /* encrypted data */
				      MAX_RSA_KEY_BYTES,       	/* size of encrypted data buffer */
				      (uint8_t *)&extra->salt.t.buffer, /* decrypted data */
				      extra->salt.t.size,
				      publicArea->unique.rsa.t.buffer,  /* public modulus */
				      publicArea->unique.rsa.t.size,
				      earr,           			/* public exponent */
				      sizeof(earr),
				      (unsigned char *)"SECRET",	/* encoding parameter */
				      sizeof("SECRET"),
				      publicArea->nameAlg);
	}    
	if (rc == 0) {
	    in->encryptedSalt.t.size = publicArea->unique.rsa.t.size;
	    if (tssVverbose) TSS_PrintAll("TSS_PR_StartAuthSession: encrypted salt",
					  in->encryptedSalt.t.secret,
					  in->encryptedSalt.t.size);
	}    
    }
    return rc;
}

static TPM_RC TSS_PR_PolicySigned(TSS_CONTEXT *tssContext,
				  PolicySigned_In *in,
				  PolicySigned_Extra *extra)
{
    TPM_RC 	rc = 0;
    TPMT_HA 	digest;
    tssContext = tssContext;

    if (tssVverbose) printf("TSS_PR_PolicySigned\n");
    /* marshal the parameters to be signed */
    /* NOTE 2	The arg2.size and arg3.size fields are not included in the hashes. */
    if (rc == 0) {
	INT32 expirationNbo = htonl(in->expiration);
	digest.hashAlg = in->auth.signature.rsassa.hash;
	/* aHash = HauthAlg(nonceTPM || expiration || cpHashA || policyRef)	(13) */
	rc = TSS_Hash_Generate(&digest,		/* largest size of a digest */
			       in->nonceTPM.t.size, in->nonceTPM.t.buffer,
			       sizeof(INT32), &expirationNbo,
			       in->cpHashA.t.size, in->cpHashA.t.buffer,
			       in->policyRef.t.size, in->policyRef.t.buffer,
			       0, NULL);
    }
    /* call back to the application to sign */
    /* add the result to the parameters */
    if (rc == 0) {
	rc = extra->signatureCallback(&digest,
				      (uint8_t *)in->auth.signature.rsassa.sig.t.buffer,
				      &in->auth.signature.rsassa.sig.t.size); 
    }
    return rc;
}

static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra)
{
    TPM_RC 	rc = 0;
    tssContext = tssContext;
    extra = extra;

    if (tssVverbose) printf("TSS_PR_NV_DefineSpace\n");
    /* Test that TPMA_NVA_POLICY_DELETE is only set when a policy is also set.  Otherwise, the index
       cannot ever be deleted, even with Platform Authorization. If the application really wants to
       do this, set the policy to one that cannot be satisfied, e.g., all 0xff's. */
    if (rc == 0) {
	if (in->publicInfo.t.nvPublic.attributes.val & TPMA_NVA_POLICY_DELETE) {
	    if (in->publicInfo.t.nvPublic.authPolicy.b.size == 0) {
		if (tssVverbose) printf("TSS_PR_NV_DefineSpace POLICY_DELETE requires a policy\n");
		rc = TSS_RC_IN_PARAMETER;
	    }
	}
    }
    return rc;
}

/*
  Response Post Processor
*/

/* TSS_Response_PostProcessor() handles any response specific post processing
 */

static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA_PARAMETERS *extra)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_PostProcessFunction_t 	postProcessFunction = NULL;

    /* search the table for a post processing function */
    if (rc == 0) {
	TPM_CC commandCode = TSS_GetCommandCode(tssContext->tssAuthContext);
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no post processing function.  This permits the table to be smaller
       if desired. */
    if ((rc == 0) && found) {
	postProcessFunction = tssTable[index].postProcessFunction;
	/* there could also be an entry that it currently NULL, nothing to do */
	if (postProcessFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the function */
    if ((rc == 0) && found) {
	rc = postProcessFunction(tssContext, in, out, extra);
    }
    return rc;
}

/*
  Command specific post processing functions
*/

/* TSS_PO_StartAuthSession handles StartAuthSession post processing.  It:

   creates a TSS HMAC session

   saves the session handle, hash algorithm, and symmetric algorithm, nonceCaller and nonceTPM
   
   It calculates the session key and saves it

   Finally, it marshals the session and stores it
*/

static TPM_RC TSS_PO_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Out *out,
				      StartAuthSession_Extra *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	*session = NULL;
    TPM2B_DIGEST 		salt;
    
    if (tssVverbose) printf("TSS_PO_StartAuthSession\n");
    /* allocate a TSS_HMAC_CONTEXT session context */
    if (rc == 0) {
	rc = TSS_HmacSession_GetContext(&session);
    }
    if (rc == 0) {
	session->sessionHandle = out->sessionHandle;
	session->authHashAlg = in->authHash;
	session->sizeInBytes = TSS_GetDigestSize(session->authHashAlg);
	session->symmetric = in->symmetric;
	session->sessionType = in->sessionType;
    }
    /* if not a bind session or if no bind password was supplied */
    if (rc == 0) {
	if ((extra == NULL) || (in->bind == TPM_RH_NULL) || (extra->bindPassword == NULL)) {
	    session->bindAuthValue.b.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&session->bindAuthValue.b,
				      extra->bindPassword, sizeof(TPMU_HA));
	}
    }
    if (rc == 0) {
	/* if the caller did not supply extra, the salt must be empty */
	if (extra == NULL) {
	    salt.b.size = 0;
	}
	/* if the caller supplied extra, the preprocessor sets salt to empty (unsalted) or the
	   plaintext salt value */
	else {
	    rc = TSS_TPM2B_Copy(&salt.b, &extra->salt.b, sizeof(TPMT_HA));
	}
    }
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->nonceTPM.b, &out->nonceTPM.b, sizeof(TPMT_HA));
    }
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->nonceCaller.b, &in->nonceCaller.b, sizeof(TPMT_HA));
    }
    if (rc == 0) {
	rc = TSS_HmacSession_SetSessionKey(tssContext, session,
					   &salt,
					   in->bind, &session->bindAuthValue);
    }
    if (rc == 0) {
	rc = TSS_HmacSession_SaveSession(tssContext, session);
    }
    TSS_HmacSession_FreeContext(session);
    return rc;
}

/* TSS_PO_ContextSave() saves the name of an object in a filename that is a hash of the contextBlob.

   This permits the name to be found during ContextLoad.
*/

static TPM_RC TSS_PO_ContextSave(TSS_CONTEXT *tssContext,
				 ContextSave_In *in,
				 ContextSave_Out *out,
				 void *extra)
{
    TPM_RC 		rc = 0;
    TPMT_HA 		cpHash;		/* largest size of a digest */
    char		string[65];	/*  sha256 hash * 2 + 1 */
    TPM_HT 		handleType;
    int			done = FALSE;

    in = in;
    extra = extra;

    /* only for objects and sequence objects, not sessions */
    if (rc == 0) {
	handleType = (TPM_HT) ((in->saveHandle & HR_RANGE_MASK) >> HR_SHIFT);
	if (handleType != TPM_HT_TRANSIENT) {
	    done = TRUE;
	}
    }
    if ((rc == 0) && !done) {
	cpHash.hashAlg = TPM_ALG_SHA256;	/* arbitrary choice */
	rc = TSS_Hash_Generate(&cpHash,
			       out->context.contextBlob.b.size, out->context.contextBlob.b.buffer,
			       0, NULL);
    }
    /* convert a hash of the context blob to a string */
    if ((rc == 0) && !done) {
	rc = TSS_HashToString(string, cpHash.digest.sha256);
    }
    if ((rc == 0) && !done) {
	rc = TSS_Name_Copy(tssContext,
			   0, string,			/* to context */
			   in->saveHandle, NULL);	/* from handle */
    }
    /* get the public key of the object being context saved */
    /* save the public key under the context */
    if ((rc == 0) && !done) {
	rc = TSS_Public_Copy(tssContext,
			     0,
			     string,
			     in->saveHandle,
			     NULL);
    }
    return rc;
}

static TPM_RC TSS_PO_ContextLoad(TSS_CONTEXT *tssContext,
				 ContextLoad_In *in,
				 ContextLoad_Out *out,
				 void *extra)
{
    TPM_RC 		rc = 0;
    TPMT_HA 		cpHash;		/* largest size of a digest */
    char		string[65];	/*  sha256 hash * 2 + 1 */
    TPM_HT 		handleType;
    int			done = FALSE;

    out = out;
    extra = extra;

    /* only for objects and sequence objects, not sessions */
    if (rc == 0) {
	handleType = (TPM_HT) ((out->loadedHandle & HR_RANGE_MASK) >> HR_SHIFT);
	if (handleType != TPM_HT_TRANSIENT) {
	    done = TRUE;
	}
    }
    if ((rc == 0) && !done) {
	cpHash.hashAlg = TPM_ALG_SHA256;	/* arbitrary choice */
	rc = TSS_Hash_Generate(&cpHash,
			       in->context.contextBlob.b.size, in->context.contextBlob.b.buffer,
			       0, NULL);
    }
    /* convert a hash of the context blob to a string */
    if ((rc == 0) && !done) {
	rc = TSS_HashToString(string, cpHash.digest.sha256);
    }
    /* get the Name of the object being context loaded */
    /* write the name with the loaded context's handle */
    if ((rc == 0) && !done) {
	rc = TSS_Name_Copy(tssContext,
			   out->loadedHandle, NULL,	/* to handle */
			   0, string);			/* from context */	
    }
    /* get the public key of the object being context loaded */
    /* write the public key with the loaded context's handle */
    if ((rc == 0) && !done) {
	rc = TSS_Public_Copy(tssContext,
			     out->loadedHandle,
			     NULL,
			     0,
			     string);
    }
    return rc;
}

/* TSS_HashToString() converts a SHA-256 binary hash (really any 32-byte value) to a string 

   string must be 65 bytes: 32*2 + 1

   NOTE: Hard coded to SHA256
*/

static TPM_RC TSS_HashToString(char *str, uint8_t *digest)
{
    size_t i;

    for (i = 0 ; i < SHA256_DIGEST_SIZE ; i++) {
	sprintf(str +(i*2), "%02x", digest[i]);
    }
    if (tssVverbose) printf("TSS_HashToString: %s\n", str);
    return 0;
}

/* TSS_PO_FlushContext() removes persistent state associated with the handle */

static TPM_RC TSS_PO_FlushContext(TSS_CONTEXT *tssContext,
				  FlushContext_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_FlushContext: flushHandle %08x\n", in->flushHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->flushHandle);
    }
    return rc;
}

/* TSS_PO_EvictControl() removes persistent state associated with the handle */

static TPM_RC TSS_PO_EvictControl(TSS_CONTEXT *tssContext,
				  EvictControl_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    
    if (tssVverbose) printf("TSS_PO_EvictControl: object %08x persistent %08x\n",
			    in->objectHandle, in->persistentHandle);
    /* if it successfully made a persistent copy */
    if (in->objectHandle != in->persistentHandle) {
	/* TPM2B_PUBLIC	bPublic; */
	if (rc == 0) {
	    rc = TSS_Name_Copy(tssContext,
			       in->persistentHandle, NULL,	/* to persistent handle */
			       in->objectHandle, NULL);		/* from transient handle */	
	}
	/* get the transient object public key */
	/* copy it to the persistent object public key */
	if (rc == 0) {
	    rc = TSS_Public_Copy(tssContext,
				 in->persistentHandle,
				 NULL,
				 in->objectHandle,
				 NULL);
	}
    }
    /* if it successfully evicted the persistent object */
    else {
	if (rc == 0) {
	    rc = TSS_DeleteHandle(tssContext, in->persistentHandle);
	}
    }
    return rc;
}

/* TSS_PO_Load() saves the Name returned for the loaded object.  It saves the TPM2B+PUBLIC */

static TPM_RC TSS_PO_Load(TSS_CONTEXT *tssContext,
			  Load_In *in,
			  Load_Out *out,
			  void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_Load: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &in->inPublic, out->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_LoadExternal() saves the Name returned for the loaded object */

static TPM_RC TSS_PO_LoadExternal(TSS_CONTEXT *tssContext,
				  LoadExternal_In *in,
				  LoadExternal_Out *out,
				  void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_LoadExternal: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &in->inPublic, out->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_HashSequenceStart() saves the Name returned for the started sequence object */

static TPM_RC TSS_PO_HashSequenceStart(TSS_CONTEXT *tssContext,
				       HashSequenceStart_In *in,
				       HashSequenceStart_Out *out,
				       void *extra)
{
    TPM_RC 	rc = 0;
    TPM2B_NAME 	name;

    in = in;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_HashSequenceStart\n");
    /* Part 1 Table 3 The Name of a sequence object is an Empty Buffer */
    if (rc == 0) {
	name.b.size = 0;
	/* use handle as file name */
	rc = TSS_Name_Store(tssContext, &name, out->sequenceHandle, NULL);
    }
    return rc;
}


/* TSS_PO_HMAC_Start() saves the Name returned for the started sequence object */

static TPM_RC TSS_PO_HMAC_Start(TSS_CONTEXT *tssContext,
				HMAC_Start_In *in,
				HMAC_Start_Out *out,
				void *extra)
{
    TPM_RC 	rc = 0;
    TPM2B_NAME 	name;

    in = in;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_HMAC_Start\n");
    /* Part 1 Table 3 The Name of a sequence object is an Empty Buffer */
    if (rc == 0) {
	name.b.size = 0;
	/* use handle as file name */
	rc = TSS_Name_Store(tssContext, &name, out->sequenceHandle, NULL);
    }
    return rc;
}

static TPM_RC TSS_PO_SequenceComplete(TSS_CONTEXT *tssContext,
				      SequenceComplete_In *in,
				      SequenceComplete_Out *out,
				      void *extra)
{
    TPM_RC 	rc = 0;

    out = out;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_SequenceComplete: sequenceHandle %08x\n", in->sequenceHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->sequenceHandle);
    }
    return rc;
}
static TPM_RC TSS_PO_EventSequenceComplete(TSS_CONTEXT *tssContext,
					   EventSequenceComplete_In *in,
					   EventSequenceComplete_Out *out,
					   void *extra)
{
    TPM_RC 	rc = 0;
    out = out;
    extra = extra;
    if (tssVverbose)
	printf("TSS_PO_EventSequenceComplete: sequenceHandle %08x\n", in->sequenceHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->sequenceHandle);
    }
    return rc;
}

static TPM_RC TSS_PO_PolicyAuthValue(TSS_CONTEXT *tssContext,
				     PolicyAuthValue_In *in,
				     void *out,
				     void *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	session;
    
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_PolicyAuthValue\n");
    if (rc == 0) {
	rc = TSS_HmacSession_LoadSession(tssContext, &session, in->policySession);
    }
    if (rc == 0) {
	session.isPasswordNeeded = FALSE;
	session.isAuthValueNeeded = TRUE;
	rc = TSS_HmacSession_SaveSession(tssContext, &session);
    }
    return rc;
}

static TPM_RC TSS_PO_PolicyPassword(TSS_CONTEXT *tssContext,
				    PolicyPassword_In *in,
				    void *out,
				    void *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	session;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_PolicyPassword\n");
    if (rc == 0) {
	rc = TSS_HmacSession_LoadSession(tssContext, &session, in->policySession);
    }
    if (rc == 0) {
	session.isPasswordNeeded = TRUE;
	session.isAuthValueNeeded = FALSE;
	rc = TSS_HmacSession_SaveSession(tssContext, &session);
    }
    return rc;
}

static TPM_RC TSS_PO_CreatePrimary(TSS_CONTEXT *tssContext,
				   CreatePrimary_In *in,
				   CreatePrimary_Out *out,
				   void *extra)
{
    TPM_RC 			rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_CreatePrimary: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &out->outPublic, out->objectHandle, NULL);
    }
    return rc;
}

static TPM_RC TSS_PO_NV_ReadPublic(TSS_CONTEXT *tssContext,
				   NV_ReadPublic_In *in,
				   NV_ReadPublic_Out *out,
				   void *extra)
{
    TPM_RC 	rc = 0;

    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_ReadPublic\n");
    
    /* validate the Name against the public area */
    /* Name = nameAlg || HnameAlg (handle->nvPublicArea)
       where
       nameAlg	algorithm used to compute Name
       HnameAlg hash using the nameAlg parameter in the NV Index location associated with handle
       nvPublicArea	contents of the TPMS_NV_PUBLIC associated with handle
    */
    {
	TPM2B_NAME name;
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &out->nvPublic.t.nvPublic);
	}
	if (rc == 0) {
	    if (name.t.size != out->nvName.t.size) {
		if (tssVerbose)
		    printf("TSS_PO_NV_ReadPublic: TPMT_NV_PUBLIC does not match TPM2B_NAME\n");
		rc = TSS_RC_MALFORMED_NV_PUBLIC;
	    }
	    else {
		int irc;
		irc = memcmp(name.t.name, out->nvName.t.name, out->nvName.t.size);
		if (irc != 0) {
		    if (tssVerbose)
			printf("TSS_PO_NV_ReadPublic: TPMT_NV_PUBLIC does not match TPM2B_NAME\n");
		    rc = TSS_RC_MALFORMED_NV_PUBLIC;
		}
	    }
	}
    }
    if (rc == 0) {
	/* use handle as file name */
	rc = TSS_Name_Store(tssContext, &out->nvName, in->nvIndex, NULL);
    }
    if (rc == 0) {
	rc = TSS_NVPublic_Store(tssContext, &out->nvPublic.t.nvPublic, in->nvIndex); 
    }
    return rc;
}

static TPM_RC TSS_PO_NV_UndefineSpace(TSS_CONTEXT *tssContext,
				      NV_UndefineSpace_In *in,
				      void *out,
				      void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_UndefineSpace\n");
    /* Don't check return code.  The name will only exist if NV_ReadPublic has been issued */
    TSS_DeleteHandle(tssContext, in->nvIndex);
    TSS_NVPublic_Delete(tssContext, in->nvIndex);
    return rc;
}

static TPM_RC TSS_PO_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     NV_UndefineSpaceSpecial_In *in,
					     void *out,
					     void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_UndefineSpaceSpecial\n");
    /* Don't check return code.  The name will only exist if NV_ReadPublic has been issued */
    TSS_DeleteHandle(tssContext, in->nvIndex);
    TSS_NVPublic_Delete(tssContext, in->nvIndex);
    return rc;
}

/* TSS_PO_NV_Write() handles the Name and NVPublic update for the 4 NV write commands: write,
   increment, extend, and setbits */

static TPM_RC TSS_PO_NV_Write(TSS_CONTEXT *tssContext,
			      NV_Write_In *in,
			      void *out,
			      void *extra)
{
    TPM_RC 			rc = 0;
    TPMS_NV_PUBLIC 		nvPublic;
    TPM2B_NAME 			name;		/* new name */
    
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_Write, Increment, Extend, SetBits:\n");

    if (rc == 0) {
	rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
    }
    /* if the previous store had written clear */
    if (!(nvPublic.attributes.val & TPMA_NVA_WRITTEN)) {
	if (rc == 0) {
	    /* set the written bit */
	    nvPublic.attributes.val |= TPMA_NVA_WRITTEN;
	    /* save the TPMS_NV_PUBLIC */
	    rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	}
	/* calculate the name */
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &nvPublic);
	}
	/* save the name */
	if (rc == 0) {
	    /* use handle as file name */
	    rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	}
	/* if there is a failure. delete the name and NVPublic */
	if (rc != 0) {
	    TSS_DeleteHandle(tssContext, in->nvIndex);
	    TSS_NVPublic_Delete(tssContext, in->nvIndex);
	}
    }
    return rc;
}

/* TSS_PO_NV_WriteLock() handles the Name and NVPublic update for the write lock command */

static TPM_RC TSS_PO_NV_WriteLock(TSS_CONTEXT *tssContext,
				  NV_WriteLock_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;
    TPMS_NV_PUBLIC 		nvPublic;
    TPM2B_NAME 			name;		/* new name */
    
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_WriteLock:\n");

    if (rc == 0) {
	rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
    }
    /* if the previous store had write lock clear */
    if (!(nvPublic.attributes.val & TPMA_NVA_WRITELOCKED)) {
	if (rc == 0) {
	    /* set the write lock bit */
	    nvPublic.attributes.val |= TPMA_NVA_WRITELOCKED;
	    /* save the TPMS_NV_PUBLIC */
	    rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	}
	/* calculate the name */
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &nvPublic);
	}
	/* save the name */
	if (rc == 0) {
	    /* use handle as file name */
	    rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	}
	/* if there is a failure. delete the name and NVPublic */
	if (rc != 0) {
	    TSS_DeleteHandle(tssContext, in->nvIndex);
	    TSS_NVPublic_Delete(tssContext, in->nvIndex);
	}
    }
    return rc;
}

/* TSS_PO_NV_WriteLock() handles the Name and NVPublic update for the read lock command */

static TPM_RC TSS_PO_NV_ReadLock(TSS_CONTEXT *tssContext,
				 NV_ReadLock_In *in,
				 void *out,
				 void *extra)
{
    TPM_RC 			rc = 0;
    TPMS_NV_PUBLIC 		nvPublic;
    TPM2B_NAME 			name;		/* new name */
    
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_ReadLock:");

    if (rc == 0) {
	rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
    }
    /* if the previous store had read lock clear */
    if (!(nvPublic.attributes.val & TPMA_NVA_READLOCKED)) {
	if (rc == 0) {
	    /* set the read lock bit */
	    nvPublic.attributes.val |= TPMA_NVA_READLOCKED;
	    /* save the TPMS_NV_PUBLIC */
	    rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	}
	/* calculate the name */
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &nvPublic);
	}
	/* save the name */
	if (rc == 0) {
	    /* use handle as file name */
	    rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	}
	/* if there is a failure. delete the name and NVPublic */
	if (rc != 0) {
	    TSS_DeleteHandle(tssContext, in->nvIndex);
	    TSS_NVPublic_Delete(tssContext, in->nvIndex);
	}
    }
    return rc;
}
