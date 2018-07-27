/********************************************************************************/
/*										*/
/*			    TPM 1.2 GetCapability				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getcapability.c 1287 2018-07-30 13:34:27Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tpmstructures12.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/Unmarshal12_fp.h>

typedef void (* USAGE_FUNCTION)(void);
typedef TPM_RC (* RESPONSE_FUNCTION)(GetCapability12_In *in, GetCapability12_Out *out);

static void printUsage(uint32_t capability);
static void usageCapability(void);
static void usageAlg(void);
static void usagePid(void);
static void usageFlag(void);
static void usageProperty(void);
static void usageSymMode(void);
static void usageKeyStatus(void);
static void usageNvIndex(void);
static void usageTransAlg(void);
static void usageHandle(void);
static void usageTransEs(void);
static void usageAuthEncrypt(void);
static void usageSelectSize(void);
static void usageDaLogic(void);

static TPM_RC printResponse(unsigned int idx, GetCapability12_In *in, GetCapability12_Out *out);

static TPM_RC responseBool(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseFlag(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseVersion(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseProperty(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseNvList(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseNvIndex(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseHandleList(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseDaLogic(GetCapability12_In *in, GetCapability12_Out *out);
static TPM_RC responseVersionVal(GetCapability12_In *in, GetCapability12_Out *out);

typedef struct {
    uint32_t capability;
    uint32_t subCapSize;
    USAGE_FUNCTION usageFunction;
    RESPONSE_FUNCTION responseFunction;
} CAPABILITY_TABLE;

static const CAPABILITY_TABLE capabilityTable [] = {
    {TPM_CAP_ORD              , 4, NULL, 		responseBool},
    {TPM_CAP_ALG              , 4, usageAlg, 		responseBool},
    {TPM_CAP_PID              , 2, usagePid, 		responseBool},
    {TPM_CAP_FLAG             , 4, usageFlag, 		responseFlag},
    {TPM_CAP_PROPERTY         , 4, usageProperty, 	responseProperty},
    {TPM_CAP_VERSION          , 0, NULL, 		responseVersion},
    {TPM_CAP_KEY_HANDLE       , 0, NULL, 		responseHandleList},
#if 0
    {TPM_CAP_CHECK_LOADED     , 4, usage, 		TYPE_BOOL},
#endif
    {TPM_CAP_SYM_MODE	  , 4, usageSymMode, 	responseBool},
    {TPM_CAP_KEY_STATUS       , 4, usageKeyStatus, 	responseBool},
    {TPM_CAP_NV_LIST          , 0, NULL, 		responseNvList},
    {TPM_CAP_MFR              , 4, NULL, 		NULL},
    {TPM_CAP_NV_INDEX         , 4, usageNvIndex, 	responseNvIndex},
    {TPM_CAP_TRANS_ALG        , 4, usageTransAlg, 	responseBool},
#if 0
    {TPM_CAP_GPIO_CHANNEL     , 2, usage, TYPE_BOOL},
#endif
    {TPM_CAP_HANDLE           , 4, usageHandle, 	responseHandleList},
    {TPM_CAP_TRANS_ES         , 2, usageTransEs, 	responseBool},
#if 0
    {TPM_CAP_MANUFACTURER_VER , 0, usage, 		TYPE_STRUCTURE},
#endif
    {TPM_CAP_AUTH_ENCRYPT     , 4, usageAuthEncrypt, 	responseBool},
    {TPM_CAP_SELECT_SIZE      , 0, usageSelectSize,	responseBool},
    {TPM_CAP_DA_LOGIC         , 2, usageDaLogic, 	responseDaLogic},
    {TPM_CAP_VERSION_VAL      , 0, NULL, 		responseVersionVal},
    {0xffffffff		      , 0, NULL, 		NULL}
};

int verbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int				i;				/* argc iterator */
    unsigned int		idx;				/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    GetCapability12_In		in;
    GetCapability12_Out		out;
    uint32_t			cap = 0;
    uint32_t			scap32;
    uint16_t			scap16;
    int 			noScap = TRUE;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-cap") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &cap);
	    }
	    else {
		printf("Missing parameter for -cap\n");
		printUsage(cap);
	    }
	}
	else if (strcmp(argv[i],"-scap") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &scap32);
		scap16 = scap32;
		noScap = FALSE;
	    }
	    else {
		printf("Missing parameter for -scap\n");
		printUsage(cap);
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage(cap);
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage(cap);
	}
    }
    if (cap == 0) {
	printf("Missing parameter -cap\n");
	printUsage(cap);
    }
    /* get table entry */
    if (rc == 0) {
	for (idx = 0 ; capabilityTable[idx].capability != 0xffffffff ; idx++) {
	    if (capabilityTable[idx].capability == cap) {
		if (capabilityTable[idx].subCapSize > 0) {
		    if (noScap) {
			printf("Missing parameter -scap\n");
			printUsage(cap);
		    }
		}
		break;
	    }
	}
	if (capabilityTable[idx].capability == 0xffffffff) {
	    printf("Unknown or unsupported -cap %08x\n", cap);
	    printUsage(cap);
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = in.subCap;
	in.capArea = cap;
	in.subCapSize = capabilityTable[idx].subCapSize;
	if (cap == TPM_CAP_SELECT_SIZE) {
	    /* marshal a TPM_SELECT_SIZE */
	    uint8_t b01 = 0x01;
	    uint8_t b02 = 0x02;
	    TSS_UINT8_Marshalu(&b01, &written, &buffer, NULL);	/* major */
	    TSS_UINT8_Marshalu(&b02, &written, &buffer, NULL);	/* minor */
	    TSS_UINT16_Marshalu(&scap16, &written, &buffer, NULL);
	    in.subCapSize = sizeof(TPM_SELECT_SIZE);
	}
	else if (in.subCapSize == 2) {
	    TSS_UINT16_Marshalu(&scap16, &written, &buffer, NULL);
	}
	else if (in.subCapSize == 4) {
	    TSS_UINT32_Marshalu(&scap32, &written, &buffer, NULL);
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	rc = printResponse(idx, &in, &out);
    }
    if (rc == 0) {
	if (verbose) printf("getcapability: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("getcapability: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(uint32_t capability)
{
    size_t i;
    
    printf("\n");
    printf("getcapability\n");
    printf("\n");
    printf("Runs TPM_GetCapability\n");
    printf("\n");
    printf("\t-cap capability Part 2 21.1\n");
    printf("\t[-subcap capability Part 2 21.2]\n");
    printf("\n");
    /* call the usage function in the capability table */
    for (i = 0 ; i < (sizeof(capabilityTable) / sizeof(CAPABILITY_TABLE)) ; i++) {
	if (capabilityTable[i].capability == capability) {
	    if (capabilityTable[i].usageFunction != NULL) {
		capabilityTable[i].usageFunction();
	    }
	    exit(1);
	}
    }
    usageCapability();
    exit(1);
}

static void usageCapability(void)
{
    printf("-cap values\n"
	   "\n"
	   "TPM_CAP_ORD             01 \n"
	   "TPM_CAP_ALG             02 \n"
	   "TPM_CAP_PID             03 \n"
	   "TPM_CAP_FLAG            04 \n"
	   "TPM_CAP_PROPERTY        05 \n"
	   "TPM_CAP_VERSION         06 \n"
	   "TPM_CAP_KEY_HANDLE      07 \n"
	   "TPM_CAP_CHECK_LOADED    08 \n"
	   "TPM_CAP_SYM_MODE        09 \n"
	   "TPM_CAP_KEY_STATUS      0C \n"
	   "TPM_CAP_NV_LIST         0D \n"
	   "TPM_CAP_MFR             10 \n"
	   "TPM_CAP_NV_INDEX        11 \n"
	   "TPM_CAP_TRANS_ALG       12 \n"
	   "TPM_CAP_HANDLE          14 \n"
	   "TPM_CAP_TRANS_ES        15 \n"
	   "TPM_CAP_AUTH_ENCRYPT    17 \n"
	   "TPM_CAP_SELECT_SIZE     18 \n"
	   "TPM_CAP_DA_LOGIC        19 \n"
	   "TPM_CAP_VERSION_VAL     1A \n"
	   "\n"
	   );
    return;
}

static void usageAlg(void)
{
    printf("TPM_CAP_ALGS -scap values\n"
	   "\n"
	   "TPM_ALG_RSA          1 \n"
	   "TPM_ALG_DES          2 \n"
	   "TPM_ALG_3DES         3 \n"
	   "TPM_ALG_SHA          4 \n"
	   "TPM_ALG_HMAC         5 \n"
	   "TPM_ALG_AES128       6 \n"
	   "TPM_ALG_MGF1         7 \n"
	   "TPM_ALG_AES192       8 \n"
	   "TPM_ALG_AES256       9 \n"
	   "TPM_ALG_XOR          A \n"
	   "\n"
	   );
   return;
}

static void usagePid(void)
{
    printf("TPM_CAP_PID -scap values\n"
	   "\n"             
	   "TPM_PID_NONE            0 \n"
	   "TPM_PID_OIAP            1 \n"
	   "TPM_PID_OSAP            2 \n"
	   "TPM_PID_ADIP            3 \n"
	   "TPM_PID_ADCP            4 \n"
	   "TPM_PID_OWNER           5 \n"
	   "TPM_PID_DSAP            6 \n"
	   "TPM_PID_TRANSPORT       7 \n"
	   );
    return;
}
static void usageFlag(void)
{
    printf("TPM_CAP_FLAG -scap values\n"
	   "\n"                        
	   "TPM_CAP_FLAG_PERMANENT 	108 \n"
	   "TPM_CAP_FLAG_VOLATILE	109 \n"
	   );
    return;
}
static void usageProperty(void)
{
    printf("TPM_CAP_PROPERTY -scap values\n"
	   "\n"                    
	   "TPM_CAP_PROP_PCR		101 \n"
	   "TPM_CAP_PROP_DIR		102 \n"
	   "TPM_CAP_PROP_MANUFACTURER	103 \n"
	   "TPM_CAP_PROP_KEYS		104 \n"
	   "TPM_CAP_PROP_MIN_COUNTER	107 \n"
	   "TPM_CAP_PROP_AUTHSESS		10A \n"
	   "TPM_CAP_PROP_TRANSESS		10B \n"
	   "TPM_CAP_PROP_COUNTERS		10C \n"
	   "TPM_CAP_PROP_MAX_AUTHSESS	10D \n"
	   "TPM_CAP_PROP_MAX_TRANSESS	10E \n"
	   "TPM_CAP_PROP_MAX_COUNTERS	10F \n"
	   "TPM_CAP_PROP_MAX_KEYS		110 \n"
	   "TPM_CAP_PROP_OWNER		111 \n"
	   "TPM_CAP_PROP_CONTEXT		112 \n"
	   "TPM_CAP_PROP_MAX_CONTEXT	113 \n"
	   "TPM_CAP_PROP_FAMILYROWS		114 \n"
	   "TPM_CAP_PROP_TIS_TIMEOUT	115 \n"
	   "TPM_CAP_PROP_STARTUP_EFFECT	116 \n"
	   "TPM_CAP_PROP_DELEGATE_ROW	117 \n"
	   "TPM_CAP_PROP_MAX_DAASESS	119 \n"
	   "TPM_CAP_PROP_DAASESS		11A \n"
	   "TPM_CAP_PROP_CONTEXT_DIST	11B \n"
	   "TPM_CAP_PROP_DAA_INTERRUPT	11C \n"
	   "TPM_CAP_PROP_SESSIONS		11D \n"
	   "TPM_CAP_PROP_MAX_SESSIONS	11E \n"
	   "TPM_CAP_PROP_CMK_RESTRICTION	11F \n"
	   "TPM_CAP_PROP_DURATION		120 \n"
	   "TPM_CAP_PROP_ACTIVE_COUNTER	122 \n"
	   "TPM_CAP_PROP_MAX_NV_AVAILABLE	123 \n"
	   "TPM_CAP_PROP_INPUT_BUFFER	124 \n"
	   );
    return;
}

static void usageSymMode(void)
{
    printf("TPM_CAP_SYM_MODE -scap values\n"
	   "\n"              	  
	   "TPM_SYM_MODE_ECB	1 \n"
	   "TPM_SYM_MODE_CBC	2 \n"
	   "TPM_SYM_MODE_CFB	3 \n"
	   );
    return;
}

static void usageKeyStatus(void)
{
    printf("TPM_CAP_KEY_STATUS -scap value is key handle\n");
    return;
}

static void usageNvIndex(void)
{
    printf("TPM_CAP_NV_INDEX -scap value is NV index handle\n");
    return;
}

static void usageTransAlg(void)
{
    printf("TPM_CAP_TRANS_ALG -scap values\n"
	   "\n"
	   "TPM_ALG_RSA      1 \n"
	   "TPM_ALG_DES      2 \n"
	   "TPM_ALG_3DES     3 \n"
	   "TPM_ALG_SHA      4 \n"
	   "TPM_ALG_HMAC     5 \n"
	   "TPM_ALG_AES128   6 \n"
	   "TPM_ALG_MGF1     7 \n"
	   "TPM_ALG_AES192   8 \n"
	   "TPM_ALG_AES256   9 \n"
	   "TPM_ALG_XOR      A \n"
	   "\n"
	   );
    return;
}

static void usageHandle(void)
{
    printf("TPM_CAP_HANDLE -scap values\n"
	   "\n"
           "TPM_RT_KEY      1 \n"  
	   "TPM_RT_AUTH     2 \n" 
	   "TPM_RT_HASH     3 \n" 
	   "TPM_RT_TRANS    4 \n"
	   "TPM_RT_CONTEXT  5 \n"
	   "TPM_RT_COUNTER  6 \n"
	   "TPM_RT_DELEGATE 7 \n"
	   "TPM_RT_DAA_TPM  8 \n"
	   "TPM_RT_DAA_V0   9 \n"
	   "TPM_RT_DAA_V1   A \n" 
	   "\n"
	   );
   return;
}

static void usageTransEs(void)
{
    printf("TPM_CAP_TRANS_ES -scap values\n"
	   "\n"
	   "TPM_ES_NONE                     1 \n"  
	   "TPM_ES_RSAESPKCSv15             2 \n" 
	   "TPM_ES_RSAESOAEP_SHA1_MGF1      3 \n" 
	   "TPM_ES_SYM_CTR                  4 \n" 
	   "TPM_ES_SYM_OFB                  5 \n"
	   );
    return;
}

static void usageAuthEncrypt(void)
{
    printf("TPM_CAP_AUTH_ENCRYPT -scap values\n"
	   "\n"
	   "TPM_ALG_RSA     1 \n"
	   "TPM_ALG_DES     2 \n"
	   "TPM_ALG_3DES    3 \n"
	   "TPM_ALG_SHA     4 \n"
	   "TPM_ALG_HMAC    5 \n"
	   "TPM_ALG_AES128  6 \n"
	   "TPM_ALG_MGF1    7 \n"
	   "TPM_ALG_AES192  8 \n"
	   "TPM_ALG_AES256  9 \n"
	   "TPM_ALG_XOR     A \n"
	   "\n"
	   );
    return;
}

static void usageSelectSize(void)
{
    printf("TPM_CAP_SELECT_SIZE -scap value is select size\n");
    return;
}

static void usageDaLogic(void)
{
    printf("TPM_CAP_DA_LOGIC -scap values\n"
	   "\n"
	   "TPM_ET_KEYHANDLE        0x01 \n"
	   "TPM_ET_OWNER            0x02 \n"
	   "TPM_ET_DATA             0x03 \n"
	   "TPM_ET_SRK              0x04 \n"
	   "TPM_ET_KEY              0x05 \n"
	   "TPM_ET_REVOKE           0x06 \n"
	   "TPM_ET_DEL_OWNER_BLOB   0x07 \n"
	   "TPM_ET_DEL_ROW          0x08 \n"
	   "TPM_ET_DEL_KEY_BLOB     0x09 \n"
	   "TPM_ET_COUNTER          0x0A \n"
	   "TPM_ET_NV               0x0B \n"
	   "TPM_ET_OPERATOR         0x0C \n"
	   );
    return;
}

static TPM_RC printResponse(unsigned int idx, GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    RESPONSE_FUNCTION responseFunction = capabilityTable[idx].responseFunction;
    if (responseFunction != NULL) {
	rc = responseFunction(in, out);
    }
    else {
	printf("printResponse: Unimplemented print\n");
    }
    return rc;
}

static TPM_RC responseBool(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    in = in;
    out = out;
    printf("boolean: %u\n", out->resp[0]);
    return rc;
}

static TPM_RC responseFlag(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    uint32_t scapHbo;
    scapHbo = ntohl(*(uint32_t *)(in->subCap));
    TPM_PERMANENT_FLAGS *pf = (TPM_PERMANENT_FLAGS *)out->resp;
    TPM_STCLEAR_FLAGS *sf = (TPM_STCLEAR_FLAGS *)out->resp;

    switch(scapHbo) {
      case TPM_CAP_FLAG_PERMANENT:
	printf("Permanent flags:\n");
	/* rev 62 + */
	printf("\tDisabled: %s\n",(0 == pf->disable) ? "FALSE" : "TRUE");
	printf("\tOwnership: %s\n",(0 == pf->ownership) ? "FALSE" : "TRUE");
	printf("\tDeactivated: %s\n",(0 == pf->deactivated) ? "FALSE" : "TRUE");
	printf("\tRead Pubek: %s\n",(0 == pf->readPubek) ? "FALSE" : "TRUE");
	printf("\tDisable Owner Clear: %s\n", (0 == pf->disableOwnerClear) ? "FALSE" : "TRUE");
	printf("\tAllow Maintenance: %s\n",(0 == pf->allowMaintenance) ? "FALSE" : "TRUE");
	printf("\tPhysical Presence Lifetime Lock: %s\n",
	       (0 == pf->physicalPresenceLifetimeLock) ? "FALSE" : "TRUE");
	printf("\tPhysical Presence HW Enable: %s\n",
	       (0 == pf->physicalPresenceHWEnable) ? "FALSE" : "TRUE");
	printf("\tPhysical Presence CMD Enable: %s\n",
	       (0 == pf->physicalPresenceCMDEnable) ? "FALSE" : "TRUE");
	printf("\tCEKPUsed: %s\n", (0 == pf->CEKPUsed) ? "FALSE" : "TRUE");
	printf("\tTPMpost: %s\n",(0 == pf->TPMpost) ? "FALSE" : "TRUE");
	printf("\tTPMpost Lock: %s\n", (0 == pf->TPMpostLock) ? "FALSE" : "TRUE");
	printf("\tFIPS: %s\n",(0 == pf->FIPS) ? "FALSE" : "TRUE");
	printf("\tOperator: %s\n", (0 == pf->tpmOperator) ? "FALSE" : "TRUE");
	printf("\tEnable Revoke EK: %s\n", (0 == pf->enableRevokeEK) ? "FALSE" : "TRUE");
	/* Atmel rev 85 only returns 18 BOOLs */
	if (out->respSize > 19) {
	    printf("\tNV Locked: %s\n",( 0 == pf->nvLocked) ? "FALSE" : "TRUE");
	    printf("\tRead SRK pub: %s\n",(0 == pf->readSRKPub) ? "FALSE" : "TRUE");
	    printf("\tTPM established: %s\n",(0 == pf->tpmEstablished) ? "FALSE" : "TRUE");
	}
	/* rev 85 + */
	if (out->respSize > 20) {
	    printf("\tMaintenance done: %s\n",(0 == pf->maintenanceDone) ? "FALSE" : "TRUE");
	}	    
	/* rev 103 */
	if (out->respSize > 21) {
	    printf("\tDisable full DA logic info: %s\n",(0 == pf->disableFullDALogicInfo) ? "FALSE" : "TRUE");
	}
	break;
      case TPM_CAP_FLAG_VOLATILE:
	printf("Volatile flags:\n");
	printf("\tDeactivated: %s\n",(0 == sf->deactivated) ? "FALSE" : "TRUE");
	printf("\tDisable ForceClear: %s\n",(0 == sf->disableForceClear) ? "FALSE" : "TRUE");
	printf("\tPhysical Presence: %s\n",(0 == sf->physicalPresence) ? "FALSE" : "TRUE");
	printf("\tPhysical Presence Lock: %s\n",(0 == sf->physicalPresenceLock) ? "FALSE" : "TRUE");
	printf("\tbGlobal Lock: %s\n",(0 == sf->bGlobalLock) ? "FALSE" : "TRUE");
	break;
      default:
	printf("responseFlag: Subcap 08x %unknown\n", scapHbo);
    }
    return rc;
}

static TPM_RC responseVersion(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    in = in;
    TPM_STRUCT_VER *sv = (TPM_STRUCT_VER *)out->resp;	/* just bytes */
    printf("TPM_CAP_VERSION: major %02x\n", sv->major);
    printf("TPM_CAP_VERSION: minor %02x\n", sv->minor);
    printf("TPM_CAP_VERSION: revMajor %02x\n", sv->revMajor);
    printf("TPM_CAP_VERSION: revMinor %02x\n", sv->revMinor);
    return rc;
}

static TPM_RC responseProperty(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    uint32_t scapHbo;
    scapHbo = ntohl(*(uint32_t *)(in->subCap));
    switch(scapHbo) {
      case TPM_CAP_PROP_PCR:
	printf("TPM_CAP_PROP_PCR: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_DIR:
	printf("TPM_CAP_PROP_DIR: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MANUFACTURER:
	printf("TPM_CAP_PROP_MANUFACTURER: %c%c%c%c\n",
	       out->resp[0], out->resp[1], out->resp[2], out->resp[3]);
	break;
      case TPM_CAP_PROP_KEYS:
	printf("TPM_CAP_PROP_KEYS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MIN_COUNTER:
	printf("TPM_CAP_PROP_MIN_COUNTER: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_AUTHSESS:
	printf("TPM_CAP_PROP_AUTHSESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_TRANSESS:
	printf("TPM_CAP_PROP_TRANSESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_COUNTERS:
	printf("TPM_CAP_PROP_COUNTERS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_AUTHSESS:
	printf("TPM_CAP_PROP_MAX_AUTHSESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_TRANSESS:
	printf("TPM_CAP_PROP_MAX_TRANSESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_COUNTERS:
	printf("TPM_CAP_PROP_MAX_COUNTERS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_KEYS:
	printf("TPM_CAP_PROP_MAX_KEYS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_OWNER:
	printf("TPM_CAP_PROP_OWNER: %u\n", out->resp[0]);
	break;
      case TPM_CAP_PROP_CONTEXT:
	printf("TPM_CAP_PROP_CONTEXT: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_CONTEXT:
	printf("TPM_CAP_PROP_MAX_CONTEXT: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_FAMILYROWS:
	printf("TPM_CAP_PROP_FAMILYROWS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_TIS_TIMEOUT:
	printf("TPM_CAP_PROP_TIS_TIMEOUT: %u %u %u %u\n",
	       ntohl(*(uint32_t *)(out->resp + 0)),
	       ntohl(*(uint32_t *)(out->resp + 4)),
	       ntohl(*(uint32_t *)(out->resp + 8)),
	       ntohl(*(uint32_t *)(out->resp +12))
	       );
	break;
      case TPM_CAP_PROP_STARTUP_EFFECT:
	printf("TPM_CAP_PROP_STARTUP_EFFECT: print unimplemented\n");
	break;
      case TPM_CAP_PROP_DELEGATE_ROW:
	printf("TPM_CAP_PROP_DELEGATE_ROW: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_DAASESS:
	printf("TPM_CAP_PROP_MAX_DAASESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_DAASESS:
	printf("TPM_CAP_PROP_DAASESS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_CONTEXT_DIST:
	printf("TPM_CAP_PROP_CONTEXT_DIST: %08x\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_DAA_INTERRUPT:
	printf("TPM_CAP_PROP_DAA_INTERRUPT: %u\n", out->resp[0]);
	break;
      case TPM_CAP_PROP_SESSIONS:
	printf("TPM_CAP_PROP_SESSIONS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_MAX_SESSIONS:
	printf("TPM_CAP_PROP_MAX_SESSIONS: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_CMK_RESTRICTION:
	printf("TPM_CAP_PROP_CMK_RESTRICTION: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_DURATION:
	printf("TPM_CAP_PROP_DURATION: %u %u %u\n", 
	       ntohl(*(uint32_t *)(out->resp + 0)),
	       ntohl(*(uint32_t *)(out->resp + 4)),
	       ntohl(*(uint32_t *)(out->resp + 8))
	       );
	break;
      case TPM_CAP_PROP_ACTIVE_COUNTER:
	printf("TPM_CAP_PROP_ACTIVE_COUNTER: print not implemented yet\n");
	break;
      case TPM_CAP_PROP_MAX_NV_AVAILABLE:
	printf("TPM_CAP_PROP_MAX_NV_AVAILABLE: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      case TPM_CAP_PROP_INPUT_BUFFER:
	printf("TPM_CAP_PROP_INPUT_BUFFER: %u\n", ntohl(*(uint32_t *)(out->resp)));
	break;
      default:
	printf("responseProperty: Subcap 08x %unknown\n", scapHbo);
    }
    return rc;
}

static TPM_RC responseNvList(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    uint16_t i;
    uint32_t count = (out->respSize / sizeof(uint32_t));
    in = in;

    printf("responseNvList: count %u\n", count);
    for (i = 0 ; i < count ; i++) {
	uint32_t handle = ntohl(*(uint32_t *)(out->resp + (i * sizeof(uint32_t))));
	printf("\tHandle %u %08x\n", i, handle);
    }
    return rc;
}

static TPM_RC responseNvIndex(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC 		rc = 0;
    TPM_NV_DATA_PUBLIC 	ndp;
    uint8_t 		*buffer = out->resp;
    uint32_t 		size = out->respSize;
    in = in;

    if (rc == 0) {
	rc = TSS_TPM_NV_DATA_PUBLIC_Unmarshalu(&ndp, &buffer, &size);
    }
    if (rc == 0) {
	printf("\tnvIndex               : %08X\n", ndp.nvIndex);
	printf("\tpermission.attributes : %08X\n", ndp.permission.attributes);
	printf("\tReadSTClear           : %u\n", ndp.bReadSTClear);
	printf("\tWriteSTClear          : %u\n", ndp.bWriteSTClear);
	printf("\tWriteDefine           : %u\n", ndp.bWriteDefine);
	printf("\tdataSize              : %08X = %u\n",
	       (unsigned int)ndp.dataSize, (unsigned int)ndp.dataSize);
    }
    else {
	printf("responseNvIndex: TPM_NV_DATA_PUBLIC unmarshal error\n");
    }
    return rc;
}

static TPM_RC responseHandleList(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    uint16_t i;
    uint16_t count;
    in = in;

    count = ntohs(*(uint16_t *)(out->resp));
    printf("responseHandleList: count %u\n", count);
    for (i = 0 ; i < count ; i++) {
	uint32_t handle = ntohl(*(uint32_t *)(out->resp + sizeof(uint16_t) +
					      (i * sizeof(uint32_t))));
	printf("\tHandle %u %08x\n", i, handle);
    }
    return rc;
}

static TPM_RC responseDaLogic(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    in = in;
    uint8_t 		*buffer;
    uint32_t 		size;

    /* could be either structure depending on the tag */
    TPM_STRUCTURE_TAG tag;
    if (rc == 0) {
	buffer = out->resp;
	size = out->respSize;
	rc = TSS_UINT16_Unmarshalu(&tag, &buffer, &size);
    }
    if (rc == 0) {
	buffer = out->resp;
	size = out->respSize;
	switch (tag) {
	  case TPM_TAG_DA_INFO:
	      {
		  TPM_DA_INFO da;
		  if (rc == 0) {
		      rc = TSS_TPM_DA_INFO_Unmarshalu(&da, &buffer, &size);
		  }
		  if (rc == 0) {
		      printf("\tTPM_DA_STATE %s\n", da.state ? "inactive" : "active");
		      printf("\tcurrentCount %u\n", da.currentCount);
		      printf("\tthresholdCount %u \n", da.thresholdCount);
		      printf("\tTPM_DA_ACTION_FAILURE_MODE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_FAILURE_MODE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_DEACTIVATE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_DEACTIVATE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_DISABLE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_DISABLE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_TIMEOUT %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_TIMEOUT)
			     ? "TRUE" : "FALSE");
		      printf("\tactionDependValue %u\n", da.actionDependValue);
		      TSS_PrintAll("\tvendorData", da.vendorData, da.vendorDataSize);
		  }
		  break;
	      }
	  case TPM_TAG_DA_INFO_LIMITED:
	      {
		  TPM_DA_INFO_LIMITED da;
		  if (rc == 0) {
		      rc = TSS_TPM_DA_INFO_LIMITED_Unmarshalu(&da, &buffer, &size);
		  }
		  if (rc == 0) {
		      printf("\tTPM_DA_STATE %s\n", da.state ? "inactive" : "active");
		      printf("\tTPM_DA_ACTION_FAILURE_MODE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_FAILURE_MODE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_DEACTIVATE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_DEACTIVATE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_DISABLE %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_DISABLE)
			     ? "TRUE" : "FALSE");
		      printf("\tTPM_DA_ACTION_TIMEOUT %s\n",
			     (da.actionAtThreshold.actions & TPM_DA_ACTION_TIMEOUT)
			     ? "TRUE" : "FALSE");
		      TSS_PrintAll("\tvendorData", da.vendorData, da.vendorDataSize);
		  }
		  break;
	      }
	  default:
	    printf("responseDaLogic: unknown structure tag %04x\n", tag); 
	}
    }
    else {
	printf("responseDaLogic: response unmarshal error\n");
    }
    return rc;
}

static TPM_RC responseVersionVal(GetCapability12_In *in, GetCapability12_Out *out)
{
    TPM_RC rc = 0;
    in = in;
    TPM_CAP_VERSION_INFO vi;
    if (rc == 0) {
	uint8_t *buffer = out->resp;
	uint32_t size = out->respSize;
	rc = TSS_TPM_CAP_VERSION_INFO_Unmarshalu(&vi, &buffer, &size);
    }
    if (rc == 0) {
	printf("\tmajor %02x\n", vi.version.major);
	printf("\tminor %02x\n", vi.version.minor);
	printf("\trevMajor %02x\n", vi.version.revMajor);
	printf("\trevMinor %02x\n", vi.version.revMinor);
	printf("\tspecLevel %u\n", vi.specLevel);
	printf("\terrataRev %u\n", vi.errataRev);
	printf("\ttpmVendorID %02x %02x %02x %02x %c%c%c%c\n",
	       vi.tpmVendorID[0], vi.tpmVendorID[1], vi.tpmVendorID[2], vi.tpmVendorID[3],
	       vi.tpmVendorID[0], vi.tpmVendorID[1], vi.tpmVendorID[2], vi.tpmVendorID[3]);
	TSS_PrintAll("\tvendorSpecific", vi.vendorSpecific, vi.vendorSpecificSize);
    }
    return rc;
}

