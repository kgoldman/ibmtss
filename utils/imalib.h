/********************************************************************************/
/*										*/
/*			     	IMA Routines					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2024					*/
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

#ifndef IMA_H
#define IMA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/TPM_Types.h>

/* FIXME need OS independent value */
/* Debian/Hurd does not define MAXPATHLEN */
#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

#define IMA_PCR 		10
/* IMA currently supports only SHA-1 and SHA-256 */
#define IMA_PCR_BANKS		2

/* FIXME need verification */
#define TCG_EVENT_NAME_LEN_MAX	255

#define TCG_TEMPLATE_DATA_LEN_MAX (sizeof(ImaTemplateData))

/* from security/integrity/integrity.h: */

enum evm_ima_xattr_type {
    IMA_XATTR_DIGEST = 0x01,
    EVM_XATTR_HMAC,
    EVM_IMA_XATTR_DIGSIG,
    IMA_XATTR_DIGEST_NG,
    IMA_XATTR_LAST
};

/* from include/uapi/linux/hash_info.h: */

enum hash_algo {
    HASH_ALGO_MD4,
    HASH_ALGO_MD5,
    HASH_ALGO_SHA1,
    HASH_ALGO_RIPE_MD_160,
    HASH_ALGO_SHA256,
    HASH_ALGO_SHA384,
    HASH_ALGO_SHA512,
    HASH_ALGO_SHA224,
    HASH_ALGO_RIPE_MD_128,
    HASH_ALGO_RIPE_MD_256,
    HASH_ALGO_RIPE_MD_320,
    HASH_ALGO_WP_256,
    HASH_ALGO_WP_384,
    HASH_ALGO_WP_512,
    HASH_ALGO_TGR_128,
    HASH_ALGO_TGR_160,
    HASH_ALGO_TGR_192,
    HASH_ALGO__LAST
};

//typedef TPM_DIGEST TPM_PCRVALUE;        	/* The value inside of the PCR */

/* maximum number of callback fields for parsing and tracing */
#define IMA_PARSE_FUNCTIONS_MAX 128

/* deprecated, hard coded to sha1 */

typedef struct ImaEvent {
    uint32_t pcrIndex;
    uint8_t digest[SHA1_DIGEST_SIZE];		/* IMA hard coded to SHA-1 */
    uint32_t name_len;
    char name[TCG_EVENT_NAME_LEN_MAX + 1];
    unsigned int nameInt;			/* integer for template data handler */
    struct ima_template_desc *template_desc; 	/* template descriptor */
    uint32_t template_data_len;
    uint8_t *template_data;			/* template related data */
} ImaEvent;

/* hash agile IMA event structure */

typedef struct ImaEvent2 {
    uint32_t pcrIndex;
    uint16_t templateHashAlgId;			/* template hash */
    TPM_ALG_ID templateHashSize;		/* template hash */
    uint8_t digest[MAX_DIGEST_BUFFER];		/* template hash */
    uint32_t name_len;
    char name[TCG_EVENT_NAME_LEN_MAX + 1];
    unsigned int nameInt;			/* integer for template data handler */
    struct ima_template_desc *template_desc; 	/* template descriptor */
    uint32_t template_data_len;
    uint8_t *template_data;			/* template related data */
} ImaEvent2;

typedef struct ImaTemplateDNG {
    uint32_t hashLength;
    char hashAlg[64+1];		/* FIXME need verification */
    TPMI_ALG_HASH hashAlgId;
    uint32_t fileDataHashLength;
    uint8_t fileDataHash[SHA256_DIGEST_SIZE];
} ImaTemplateDNG;

typedef struct ImaTemplateDNGV2 {
    uint32_t hashLength;
    char prefix[64+1];
    char hashAlg[64+1];		/* FIXME need verification */
    TPMI_ALG_HASH hashAlgId;
    uint32_t fileDataHashLength;
    uint8_t fileDataHash[SHA256_DIGEST_SIZE];
} ImaTemplateDNGV2;

typedef struct ImaTemplateNNG {
    uint32_t fileNameLength;
    uint8_t fileName[MAXPATHLEN+1];
} ImaTemplateNNG;

typedef struct ImaTemplateSIG {
    uint32_t sigLength;
    uint32_t sigHeaderLength;
    uint8_t sigHeader[9];	/* FIXME need verification, length and contents */
    uint16_t signatureSize;
    uint8_t signature[256];	/* FIXME need verification */
} ImaTemplateSIG;

typedef struct ImaTemplateDMODSIG {
    uint32_t dModSigHashLength;
    char dModSigHashAlg[64+1];		/* FIXME need verification */
    TPMI_ALG_HASH dModSigHashAlgId;
    uint32_t dModSigFileDataHashLength;
    uint8_t dModSigFileDataHash[SHA256_DIGEST_SIZE];
} ImaTemplateDMODSIG;

typedef struct ImaTemplateMODSIG {
    uint32_t modSigLength;
    uint8_t modSigData[4096];	/* FIXME guess */

} ImaTemplateMODSIG;

typedef struct ImaTemplateBUF {
    uint32_t bufLength;
    uint8_t bufData[4096];	/* FIXME guess */
} ImaTemplateBUF;

/* Put the three items in one structure since they must be together and have dependencies and
   redundancies.
*/

typedef struct ImaTemplateXattrs {
    uint32_t xattrNamesLength;
    char xattrNames[256];	/* FIXME guess maximum length */
    size_t xattrNamesCount;
    char *xattrNamesPtr[32];	/* FIXME guess maxumum number of elements */
    uint32_t xattrLengthsLength;
    uint32_t xattrLengths[32];	/* FIXME guess maximum number of elements */
    uint32_t xattrLengthsSum;	/* sum of the previous array values */
    uint32_t xattrValuesLength;
    unsigned char xattrValues[4096];		/* FIXME guess */
} ImaTemplateXattrs;

typedef struct ImaTemplateIUID {
    uint32_t iuidLength;
    union {	/* u16 or u32 */
	uint16_t iuid16;
	uint32_t iuid32;
    };
} ImaTemplateIUID;

typedef struct ImaTemplateIGID {
    uint32_t igidLength;
    union {	/* u16 or u32 */
	uint16_t igid16;
	uint32_t igid32;
    };
} ImaTemplateIGID;

typedef struct ImaTemplateIMODE {
    uint32_t imodeLength;
    uint16_t imode;
} ImaTemplateIMODE;


typedef struct ImaTemplateData ImaTemplateData;

typedef void (*TemplateDataTraceFunction_t)(ImaTemplateData	*imaTemplateData);

struct ImaTemplateData {
    /* array for tracing */
    TemplateDataTraceFunction_t templateDataTraceFunctions[IMA_PARSE_FUNCTIONS_MAX];
    /* d-ng */
    ImaTemplateDNG imaTemplateDNG;
    /* d-ngv2 */
    ImaTemplateDNGV2 imaTemplateDNGV2;
    /* n-ng */
    ImaTemplateNNG imaTemplateNNG;
    /* sig */
    ImaTemplateSIG imaTemplateSIG;
    /* d-modsig */
    ImaTemplateDMODSIG imaTemplateDMODSIG;
    /* modsig */
    ImaTemplateMODSIG imaTemplateMODSIG;
    /* buf */
    ImaTemplateBUF imaTemplateBUF;
    /* xattrs */
    ImaTemplateXattrs imaTemplateXattrs;
    /* iuid */
    ImaTemplateIUID imaTemplateIUID; 
    /* igid */
    ImaTemplateIGID imaTemplateIGID; 
    /* imode */
    ImaTemplateIMODE imaTemplateIMODE; 
    /* NOTE: When adding here, update IMA_TemplateData_Init() */
};

#ifdef __cplusplus
extern "C" {
#endif

    /* deprecated SHA-1 functions */
    void IMA_Event_Init(ImaEvent *imaEvent);
    void IMA_Event_Free(ImaEvent *imaEvent);
    void IMA_Event_Trace(ImaEvent *imaEvent, int traceTemplate);
    uint32_t IMA_Event_ReadFile(ImaEvent *imaEvent,
				int *endOfFile,
				FILE *infile,
				int littleEndian);
    uint32_t IMA_Event_ReadBuffer(ImaEvent *imaEvent,
				  size_t *length,
				  uint8_t **buffer,
				  int *endOfBuffer,
				  int littleEndian,
				  int getTemplate);
    uint32_t IMA_Event_Write(ImaEvent *imaEvent,
			     FILE *outFile);
    TPM_RC IMA_Event_Marshal(ImaEvent *source,
			     uint16_t *written, uint8_t **buffer, uint32_t *size);

    uint32_t IMA_Event_PcrExtend(TPMT_HA pcrs[IMA_PCR_BANKS][IMPLEMENTATION_PCR],
				 ImaEvent *imaEvent);
#if 0
    uint32_t IMA_Event_ToString(char **eventString,
				ImaEvent *imaEvent);
#endif
    uint32_t IMA_TemplateData_ReadBuffer(ImaTemplateData *imaTemplateData,
					 ImaEvent *imaEvent,
					 int littleEndian);
    uint32_t IMA_VerifyImaDigest(uint32_t *badEvent,
				 ImaEvent *imaEvent,
				 int eventNum);
 
    /* Hash agile API */
    
    void IMA_Event2_Init(ImaEvent2 *imaEvent);
    void IMA_Event2_Free(ImaEvent2 *imaEvent);
    void IMA_Event2_Trace(ImaEvent2 *imaEvent, int traceTemplate);
    uint32_t IMA_Event2_ReadFile(ImaEvent2 *imaEvent,
				 int *endOfFile,
				 FILE *infile,
				 int littleEndian,
				 TPM_ALG_ID templateHashAlgId);
    uint32_t IMA_TemplateData2_ReadBuffer(ImaTemplateData *imaTemplateData,
					  ImaEvent2 *imaEvent,
					  int littleEndian);
    uint32_t IMA_VerifyImaDigest2(uint32_t *badEvent,
				  ImaEvent2 *imaEvent,
				  int eventNum);
 
    /* Template Data */

    void IMA_TemplateData_Init(ImaTemplateData *imaTemplateData);
    void IMA_TemplateData_Trace(ImaTemplateData *imaTemplateData,
				unsigned int nameInt);
    uint32_t IMA_Extend(TPMT_HA *imapcr,
			ImaEvent *imaEvent,
			TPMI_ALG_HASH hashAlg);

#ifdef __cplusplus
}
#endif

#endif
