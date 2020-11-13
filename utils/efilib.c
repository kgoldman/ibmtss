/********************************************************************************/
/*										*/
/*		     	EFI Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2020.						*/
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
/* SPECIAL, EXEzMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This module parses UEFI pre-OS event logs.

   A typical usage is:

   TSS_EFIData_Init() - initialize the structure
   TSS_EFIData_ReadBuffer() - unmarshal an event into the structure
   TSS_EFIData_Free() - free the structure

   After TSS_EFIData_ReadBuffer, the structure can be called with

   TSS_EFIData_Trace() to pretty print the structure to stdout

   TSS_EFIData_ToJson() to output json in some TBD format and destination.  This has not been
   mplemented.  There are placeholders.
*/

#include <stddef.h>

#include <openssl/x509.h>

#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>

#include "eventlib.h"
#include "efilib.h"

/* standard GUID values */

/* a5c059a1-94e4-4aa7-87b5-ab155c2bf072 */
#define EFI_CERT_X509_GUID				\
    {0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,	\
     0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
/* 8be4df61-93ca-11d2-aa0d-00e098032b8c */
#define EFI_GLOBAL_VARIABLE				\
    {0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,	\
     0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
/* d719b2cb-3d3a-4596-a3bc-dad00e67656f */
#define EFI_IMAGE_SECURITY_DATABASE_GUID		\
    {0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45,	\
     0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}
/* f2fd1544-9794-4a2c-992e-e5bbcf20e394 */
#define SMBIOS3_TABLE_GUID				\
    {0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a,	\
     0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}
/* 7facc7b6-127f-4e9c-9c5d-080f98994345 */
#define LENOVO2_GUID					\
    {0xb6, 0xc7, 0xac, 0x7f, 0x7f, 0x12, 0x9c, 0x4e,	\
     0x9c, 0x5d, 0x08, 0x0f, 0x98, 0x99, 0x43, 0x45}
/* 77fa9abd-0359-4d32-bd60-28f4e78f784b */
#define MICROSOFT_GUID					\
    {0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 	\
     0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}
/* 3cc24e96-22c7-41d8-8863-8e39dcdcc2cf */
#define LENOVO_GUID					\
    {0x96, 0x4e, 0xc2, 0x3c, 0xc7, 0x22, 0xd8, 0x41, 	\
     0x88, 0x63, 0x8e, 0x39, 0xdc, 0xdc, 0xc2, 0xcf}
/* 70564dce-9afc-4ee3-85fc-949649d7e45c */
#define DELL_PK_SIGNING_KEY				\
    {0xce, 0x4d, 0x56, 0x70, 0xfc, 0x9a, 0xe3, 0x4e,	\
     0x85, 0xfc, 0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}
/* c1c41626-504c-4092-aca9-41f936934328	*/
#define SHA256_GUID					\
    {0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,	\
     0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}
#define EFI_MP_SERVICES_PROTOCOL_GUID			\
    {0x05, 0xa6, 0xdd, 0x3f, 0x6e, 0xa7, 0x46, 0x4f,	\
     0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08}
/* c12a7328-f81f-11d2-ba4b-00a0c93ec93b */
#define EFI_SYSTEM_PARTITION_GUID			\
    {0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,	\
     0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b} 
/* e3c9e316-0b5c-4db8-817d-f92df00215ae */
#define MICROSOFT_RESERVED_PARTITION_GUID		\
    {0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d,	\
     0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae}
/* ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 */
#define BASIC_DATA_PARTITION_GUID			\
    {0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,	\
     0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7}
/* de94bba4-06d1-4d40-a16a-bfd50179d6ac */
#define WINDOWS_RECOVERY_ENVIRONMENT_GUID		\
    {0xa4, 0xbb, 0x94, 0xde, 0xd1, 0x06, 0x40, 0x4d,	\
     0xa1, 0x6a, 0xbf, 0xd5, 0x01, 0x79, 0xd6, 0xac}
/* 0fc63daf-8483-4772-8e79-3d69d8477de4 */
#define LINUX_FILESYSTEM_DATA_GUID			\
    {0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,	\
     0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}
/* 21686148-6449-6e6f-744e-656564454649 */
#define BIOS_BOOT_PARTITION_GUID			\
    {0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6f, 0x6e,	\
	    0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49}


#if 0	/* future GUIDs to be supported */
#define SMBIOS_TABLE_GUID    			"eb9d2d31-2d88-11d3-9a16-0090273fc14d"
#define EFI_ACPI_20_TABLE_GUID 			"8868e871-e4f1-11d3-bc22-0080c73c8881"
#define ACPI_TABLE_GUID    			"eb9d2d30-2d88-11d3-9a16-0090273fc14d"
#define SAL_SYSTEM_TABLE_GUID    		"eb9d2d32-2d88-11d3-9a16-0090273fc14d"
#define MPS_TABLE_GUID    			"eb9d2d2f-2d88-11d3-9a16-0090273fc14d"
#define EFI_JSON_CONFIG_DATA_TABLE_GUID		"87367f87-1119-41ce-aaec-8be0111f558a"
#define EFI_JSON_CAPSULE_DATA_TABLE_GUID    	"35e7a725-8dd2-4cac-8011-33cda8109056"
#define EFI_JSON_CAPSULE_RESULT_TABLE_GUID    	"dbc461c3-b3de-422a-b9b4-9886fd49a1e5"
#endif

/* GUID data types */

#define GUID_TYPE_UNSUPPORTED	0
#define GUID_TYPE_X509_CERT 	1
#define GUID_TYPE_SHA256 	2

/* This table maps GUID to the data type.  It includes the text name of the GUID for tracing. */

typedef struct {
    uint8_t guidBin[16];	/* binary */
    uint32_t type;
    const char *guidText;	/* trace text */
} GUID_TABLE;

const GUID_TABLE guidTable [] =
    {
     {EFI_CERT_X509_GUID,
      GUID_TYPE_X509_CERT,
      "EFI_CERT_X509_GUID"},
     {EFI_GLOBAL_VARIABLE,
      GUID_TYPE_UNSUPPORTED,
      "EFI_GLOBAL_VARIABLE_GUID"},
     {EFI_IMAGE_SECURITY_DATABASE_GUID,
      GUID_TYPE_X509_CERT,
      "EFI_IMAGE_SECURITY_DATABASE_GUID"},
     {SMBIOS3_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SMBIOS3_TABLE_GUID"},
     {LENOVO2_GUID,
      GUID_TYPE_UNSUPPORTED,
      "LENOVO2_GUID"},
     {MICROSOFT_GUID,
      GUID_TYPE_X509_CERT,
      "MICROSOFT_GUID"},
     {LENOVO_GUID,
      GUID_TYPE_UNSUPPORTED,
      "LENOVO_GUID"},
     {DELL_PK_SIGNING_KEY,
      GUID_TYPE_UNSUPPORTED,
      "DELL_PK_SIGNING_KEY_GUID"},
     {SHA256_GUID,
      GUID_TYPE_SHA256,
      "SHA256_GUID"},
     {EFI_MP_SERVICES_PROTOCOL_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_MP_SERVICES_PROTOCOL_GUID"},
     {EFI_SYSTEM_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_SYSTEM_PARTITION_GUID"},
     {MICROSOFT_RESERVED_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "MICROSOFT_RESERVED_PARTITION_GUID"},
     {BASIC_DATA_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "BASIC_DATA_PARTITION_GUID"},
     {WINDOWS_RECOVERY_ENVIRONMENT_GUID,
     GUID_TYPE_UNSUPPORTED,
     "WINDOWS_RECOVERY_ENVIRONMENT_GUID"},
     {LINUX_FILESYSTEM_DATA_GUID,
     GUID_TYPE_UNSUPPORTED,
     "LINUX_FILESYSTEM_DATA_GUID"},
     {BIOS_BOOT_PARTITION_GUID,
     GUID_TYPE_UNSUPPORTED,
     "BIOS_BOOT_PARTITION_GUID"},

#if 0
     {EFI_ACPI_20_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_ACPI_20_TABLE_GUID"},
     {ACPI_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "ACPI_TABLE_GUID"},
     {SAL_SYSTEM_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SAL_SYSTEM_TABLE_GUID"},
     {SMBIOS_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SMBIOS_TABLE_GUID"},
     {MPS_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "MPS_TABLE_GUID"},
     {EFI_JSON_CONFIG_DATA_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CONFIG_DATA_TABLE_GUID"},
     {EFI_JSON_CAPSULE_DATA_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CAPSaULE_DATA_TABLE_GUID"},
     {EFI_JSON_CAPSULE_RESULT_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CAPSULE_RESULT_TABLE_GUID"},
#endif
    };

static uint32_t TSS_EFI_GetGuidIndex(size_t *index, const uint8_t *guidBin);

/* Standard UC16 Variable Name strings */

const unsigned char unknown[] = "\x00";
const unsigned char secureboot[] =
    "\x53\x00\x65\x00\x63\x00\x75\x00\x72\x00\x65\x00"
    "\x42\x00\x6f\x00\x6f\x00\x74";
const unsigned char PK[]  = "\x50\x00\x4b"; 
const unsigned char KEK[] = "\x4b\x00\x45\x00\x4b";
const unsigned char db[]  = "\x64\x00\x62";
const unsigned char dbr[] = "\x64\x00\x62\x00\x72";
const unsigned char dbt[] = "\x64\x00\x62\x00\x74";
const unsigned char dbx[] = "\x64\x00\x62\x00\x78";
const unsigned char bootorder[] =
    "\x42\x00\x6f\x00\x6f\x00\x74\x00\x4f\x00\x72\x00"
    "\x64\x00\x65\x00\x72";
const unsigned char Shim[] = "\x53\x00\x68\x00\x69\x00\x6d";
const unsigned char MokList[] = "\x4d\x00\x6f\x00\x6b\x00\x4c\x00\x69\x00\x73\x00\x74";

/* This table maps UC16 Variable names to this implementation structure tags */

typedef struct {
    const unsigned char *name;
    uint32_t nameLength;
    int tag;
} TAG_TABLE;

const TAG_TABLE tagTable [] =
    {
     {unknown,
      sizeof(unknown),
      VAR_UNKNOWN},
     {secureboot,
      sizeof(secureboot),
      VAR_SECUREBOOT},
     {PK,
      sizeof(PK),
      VAR_PK},
     {KEK,
      sizeof(KEK),
      VAR_KEK},
     {db,
      sizeof(db),
      VAR_DB},
     {dbx,
      sizeof(dbx),
      VAR_DBX},
     {dbt,
      sizeof(dbt),
      VAR_DBT},
     {dbr,
      sizeof(dbr),
      VAR_DBR},
     {bootorder,
      sizeof(bootorder),
      VAR_BOOTORDER},
     {Shim,
      sizeof(Shim),
      VAR_SHIM},
     {MokList,
      sizeof(MokList),
      VAR_MOKLIST},
    };

static void TSS_EFI_GetNameIndex(size_t *index,
				 const uint8_t *name, uint64_t nameLength);

/* function prototypes for event callback table */

typedef void     (*TSS_EFIDAta_Init_Function_t)(TSST_EFIData *efiData);
typedef void     (*TSS_EFIDAta_Free_Function_t)(TSST_EFIData *efiData);
typedef uint32_t (*TSS_EFIDAta_ReadBuffer_Function_t)(TSST_EFIData *efiData,
						      uint8_t *event,
						      uint32_t eventSize,
						      uint32_t pcrIndex);
typedef void     (*TSS_EFIDAta_Trace_Function_t)(TSST_EFIData *efiData);
typedef uint32_t (*TSS_EFIDAta_ToJson_Function_t)(TSST_EFIData *efiData);

/* callback function prototypes */

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

static uint32_t TSS_EfiPlatformFirmwareBlobReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex);
static void     TSS_EfiPlatformFirmwareBlobTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlobToJson(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_DRIVER_CONFIG
   EV_EFI_VARIABLE_BOOT
   EV_EFI_VARIABLE_AUTHORITY
*/

static void     TSS_EfiVariableDataInit(TSST_EFIData *efiData);
static void     TSS_EfiVariableDataFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableDataReadBuffer(TSST_EFIData *efiData,
					      uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiVariableDataTrace(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void     TSS_EfiVariableDriverConfigInit(TSST_EFIData *efiData);
static void     TSS_EfiVariableDriverConfigFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableDriverConfigReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex);
static void     TSS_EfiVariableDriverConfigTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableDriverConfigToJson(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_BOOT */

static void     TSS_EfiVariableBootInit(TSST_EFIData *efiData);
static void     TSS_EfiVariableBootFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableBootReadBuffer(TSST_EFIData *efiData,
				       uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiVariableBootTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableBootToJson(TSST_EFIData *efiData);

static uint32_t TSS_EfiBootOrderListReadBuffer(uint16_t **bootOrderList,
					uint32_t *bootOrderListCount,
					uint8_t *VariableData, uint32_t VariableDataLength);

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

static uint32_t TSS_EfiPlatformFirmwareBlobReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex);
static void     TSS_EfiPlatformFirmwareBlobTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlobToJson(TSST_EFIData *efiData);

/* EFI_SIGNATURE_LIST within UEFI_VARIABLE_DATA */

static void     TSS_EfiSignatureListInit(EFI_SIGNATURE_LIST *signatureList);
static void     TSS_EfiSignatureListFree(EFI_SIGNATURE_LIST *signatureList);
static uint32_t TSS_EfiSignatureListReadBuffer(EFI_SIGNATURE_LIST *signatureList,
					       uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiSignatureListTrace(EFI_SIGNATURE_LIST *signatureList);

/* UEFI_VARIABLE_DATA for PK, KEK, db, dbx, dbr, dbt, etc. */
  
static uint32_t TSS_EfiSignatureAllListsReadBuffer(EFI_SIGNATURE_LIST **signatureList,
						   uint32_t *signatureListCount,
						   uint8_t *VariableData,
						   uint32_t VariableDataLength);

/* EV_EFI_VARIABLE_BOOT */

static uint32_t TSS_EfiVariableBootPathReadBuffer(uint32_t *isBootEnabled,
						  char **bootDescription,
						  char **bootPath,
						  void *VariableData, uint64_t VariableDataLength);

/* EV_EFI_VARIABLE_AUTHORITY */

static void     TSS_EfiVariableAuthorityInit(TSST_EFIData *efiData);
static void     TSS_EfiVariableAuthorityFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableAuthorityReadBuffer(TSST_EFIData *efiData,
						   uint8_t *event, uint32_t eventSize,
						   uint32_t pcrIndex);
static void     TSS_EfiVariableAuthorityTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableAuthorityToJson(TSST_EFIData *efiData);

/* EV_EFI_BOOT_SERVICES_APPLICATION
   EV_EFI_BOOT_SERVICES_DRIVER
*/

static void     TSS_EfiBootServicesInit(TSST_EFIData *efiData);
static void     TSS_EfiBootServicesFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiBootServicesReadBuffer(TSST_EFIData *efiData,
					      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiBootServicesTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiBootServicesToJson(TSST_EFIData *efiData);

/* EV_EFI_GPT_EVENT */

static void     TSS_EfiGptEventInit(TSST_EFIData *efiData);
static void     TSS_EfiGptEventFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiGptEventReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiGptEventTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiGptEventToJson(TSST_EFIData *efiData);

/* EV_EFI_GPT_EVENT */

static uint32_t TSS_EfiPartitionHeaderReadBuffer(UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader,
						 uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiPartitionEntryReadBuffer(UEFI_PARTITION_ENTRY *entry,
						uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiPartitionHeaderTrace(UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader);
static void     TSS_EfiPartitionEntryTrace(UEFI_PARTITION_ENTRY *entry);


/* EV_S_CRTM_VERSION
   EV_POST_CODE
   EV_COMPACT_HASH
*/

static void     TSS_Efi4bBufferInit(TSST_EFIData *efiData);
static void     TSS_Efi4bBufferFree(TSST_EFIData *efiData);
static uint32_t TSS_Efi4bBufferReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);

/* EV_COMPACT_HASH */

static void     TSS_EfiCompactHashTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCompactHashToJson(TSST_EFIData *efiData);

/* EV_IPL */

static void     TSS_EfiIplTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiIplToJson(TSST_EFIData *efiData);

/* EV_S_CRTM_VERSION */

static void     TSS_EfiCrtmVersionTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCrtmVersionToJson(TSST_EFIData *efiData);

/* EV_S_CRTM_CONTENTS */

static void     TSS_EfiCrtmContentsTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCrtmContentsToJson(TSST_EFIData *efiData);

/* EV_EFI_ACTION */

static void     TSS_EfiActionTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiActionToJson(TSST_EFIData *efiData);

/* EV_POST_CODE */

static uint32_t TSS_EfiCharReadBuffer(TSST_EFIData *efiData,
				      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiCharTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCharToJson(TSST_EFIData *efiData);

/* EV_SEPARATOR */

static void     TSS_EfiSeparatorTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiSeparatorToJson(TSST_EFIData *efiData);

/* EV_EFI_HANDOFF_TABLES
   EV_TABLE_OF_DEVICES
*/

static void     TSS_EfiHandoffTablesInit(TSST_EFIData *efiData);
static void     TSS_EfiHandoffTablesFree(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTablesReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize,
					       uint32_t pcrIndex);
static void     TSS_EfiHandoffTablesTrace(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTablesToJson(TSST_EFIData *efiData);

/* helper functions */

#if HAVE_EFIBOOT_H
static uint32_t TSS_EfiFormatDevicePath(char **path,
					uint8_t *devicePath,	/* efidp structure */
					uint16_t pathlen);
#endif /* HAVE_EFIBOOT_H */

static void guid_printf(const char *msg, uint8_t *v_guid);

static void wchar_printf(const char *msg, void *wchar, uint64_t length);

/* Table to map eventType to handling function callbacks.

   Missing events return an error.

   Events with NULL for initFunction or freeFunction are legal, meaning that the readBufferFunction
   will not malloc memory that needs pointers to be initialized to NULL and freed,

   NULL entries for readBufferFunction, traceFunction, or toJsonFunction are errors.
*/

typedef struct {
    uint32_t eventType;					/* PC Client event */
    TSS_EFIDAta_Init_Function_t		initFunction;
    TSS_EFIDAta_Free_Function_t		freeFunction;
    TSS_EFIDAta_ReadBuffer_Function_t	readBufferFunction;
    TSS_EFIDAta_Trace_Function_t	traceFunction;
    TSS_EFIDAta_ToJson_Function_t	toJsonFunction;
} EFI_EVENT_TYPE_TABLE;

const EFI_EVENT_TYPE_TABLE efiEventTypeTable [] =
    {
     {EV_PREBOOT_CERT,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_POST_CODE,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_EfiCharReadBuffer,
      TSS_EfiCharTrace,
      TSS_EfiCharToJson},
     {EV_UNUSED,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NO_ACTION,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_SEPARATOR,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiSeparatorTrace,
      TSS_EfiSeparatorToJson},
     {EV_ACTION,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_EVENT_TAG,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_S_CRTM_CONTENTS,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiCrtmContentsTrace,
      TSS_EfiCrtmContentsToJson},
     {EV_S_CRTM_VERSION,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiCrtmVersionTrace,
      TSS_EfiCrtmVersionToJson},
     {EV_CPU_MICROCODE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_PLATFORM_CONFIG_FLAGS,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_TABLE_OF_DEVICES,
      TSS_EfiHandoffTablesInit,
      TSS_EfiHandoffTablesFree,
      TSS_EfiHandoffTablesReadBuffer,
      TSS_EfiHandoffTablesTrace,
      TSS_EfiHandoffTablesToJson},
     {EV_COMPACT_HASH,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiCompactHashTrace,
      TSS_EfiCompactHashToJson},
     {EV_IPL,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiIplTrace,
      TSS_EfiIplToJson},
     {EV_IPL_PARTITION_DATA,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NONHOST_CODE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NONHOST_CONFIG,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NONHOST_INFO,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_OMIT_BOOT_DEVICE_EVENTS,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_EFI_VARIABLE_DRIVER_CONFIG,
      TSS_EfiVariableDriverConfigInit,
      TSS_EfiVariableDriverConfigFree,
      TSS_EfiVariableDriverConfigReadBuffer,
      TSS_EfiVariableDriverConfigTrace,
      TSS_EfiVariableDriverConfigToJson},
     {EV_EFI_VARIABLE_BOOT,
      TSS_EfiVariableBootInit,
      TSS_EfiVariableBootFree,
      TSS_EfiVariableBootReadBuffer,
      TSS_EfiVariableBootTrace,
      TSS_EfiVariableBootToJson},
     {EV_EFI_BOOT_SERVICES_APPLICATION,
      TSS_EfiBootServicesInit,
      TSS_EfiBootServicesFree,
      TSS_EfiBootServicesReadBuffer,
      TSS_EfiBootServicesTrace,
      TSS_EfiBootServicesToJson},
     {EV_EFI_BOOT_SERVICES_DRIVER,
      TSS_EfiBootServicesInit,
      TSS_EfiBootServicesFree,
      TSS_EfiBootServicesReadBuffer,
      TSS_EfiBootServicesTrace,
      TSS_EfiBootServicesToJson},
     {EV_EFI_RUNTIME_SERVICES_DRIVER,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_EFI_GPT_EVENT,
      TSS_EfiGptEventInit,
      TSS_EfiGptEventFree,
      TSS_EfiGptEventReadBuffer,
      TSS_EfiGptEventTrace,
      TSS_EfiGptEventToJson},
     {EV_EFI_ACTION,
      TSS_Efi4bBufferInit,
      TSS_Efi4bBufferFree,
      TSS_Efi4bBufferReadBuffer,
      TSS_EfiActionTrace,
      TSS_EfiActionToJson},
     {EV_EFI_PLATFORM_FIRMWARE_BLOB,
      NULL,
      NULL,
      TSS_EfiPlatformFirmwareBlobReadBuffer,
      TSS_EfiPlatformFirmwareBlobTrace,
      TSS_EfiPlatformFirmwareBlobToJson},
     {EV_EFI_HANDOFF_TABLES,
      TSS_EfiHandoffTablesInit,
      TSS_EfiHandoffTablesFree,
      TSS_EfiHandoffTablesReadBuffer,
      TSS_EfiHandoffTablesTrace,
      TSS_EfiHandoffTablesToJson},
     {EV_EFI_HCRTM_EVENT,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_EFI_VARIABLE_AUTHORITY,
      TSS_EfiVariableAuthorityInit,
      TSS_EfiVariableAuthorityFree,
      TSS_EfiVariableAuthorityReadBuffer,
      TSS_EfiVariableAuthorityTrace,
      TSS_EfiVariableAuthorityToJson},
     {EV_EFI_SUPERMICRO_1,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
    };


/* local function prototypes */

static uint32_t TSS_EFI_GetTableIndex(size_t *index, uint32_t eventType);

/* Used for input sanity check.  Keep below ffffffff so that cast to uint32_t is safe */
#define EFI_LENGTH_MAX 0x100000

/* TSS_EFIData_Init() initializes the efiData structure based on the EFI eventType so that
   TSS_EFIData_Free() is safe.

   Returns

   TSS_RC_NOT_IMPLEMENTED: eventType is not supported
   TSS_RC_OUT_OF_MEMORY: malloc failure
*/

uint32_t TSS_EFIData_Init(TSST_EFIData **efiData,	/* freed by TSS_EFIData_Free */
			  uint32_t eventType)
{
    uint32_t rc = 0;
    size_t index;

    /* if the eventType is supported */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, eventType);
    }
    /* malloc the structure */
    if (rc == 0) {
	*efiData = malloc(sizeof(TSST_EFIData));	/* freed by caller */
	if (*efiData == NULL) {
	    printf("TSS_EFIData_Init: Error allocating %u bytes\n",
		   (unsigned int)sizeof(TSST_EFIData));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	(*efiData)->eventType = eventType;
	/* if there is an initialization function */
	/* eventType specific initialization */
	if (efiEventTypeTable[index].initFunction != NULL) {
	    efiEventTypeTable[index].initFunction(*efiData);
	}
	/* NULL is not an error, means that no read malloc will occur */
    }
    return rc;
}

/* TSS_EFIData_Free() the efiData structure based on the EFI eventType. */

void TSS_EFIData_Free(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    size_t index;

    if (efiData != NULL) {
	/* a failure here is a call sequence error */
	if (rc == 0) {
	    rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
	}
	if (rc == 0) {
	    /* eventType specific free */
	    if (efiEventTypeTable[index].freeFunction != NULL) {
		efiEventTypeTable[index].freeFunction(efiData);
	    }
	    /* NULL is not an error, means that no read malloc occured */
	}
	free(efiData);
    }
    return;
}

/* TSS_EFIData_ReadBuffer() parses the event based on the EFI eventType.

   Returns TSS_RC_NOT_IMPLEMENTED if the eventType is not supported.

*/

uint32_t TSS_EFIData_ReadBuffer(TSST_EFIData *efiData,
				uint8_t *event, uint32_t eventSize,
				uint32_t pcrIndex)
{
    uint32_t rc = 0;
    size_t index;

    /* save the PCR index because some subsequent functions depend on the PCR value */
    if (rc == 0) {
	efiData->pcrIndex = pcrIndex;
    }
    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
    }
    if (rc == 0) {
	/* eventType specific read buffer */
	if (efiEventTypeTable[index].readBufferFunction != NULL) {
	    rc = efiEventTypeTable[index].readBufferFunction(efiData,
							     event, eventSize,
							     pcrIndex);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    return rc;
}

/* TSS_EFIData_Trace() traces the efiData to stdout.

   It assumes that the TSS_EFIData structure and eventType are valid.
*/

void TSS_EFIData_Trace(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    size_t index;

    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
    }
    if (rc == 0) {
	/* eventType specific traceFunction */
	if (efiEventTypeTable[index].traceFunction != NULL) {
	    efiEventTypeTable[index].traceFunction (efiData);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    return;
}

/* TSS_EFIData_ToJson() outputs the efiData to stdout as json */

uint32_t TSS_EFIData_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    size_t index;

    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
    }
    if (rc == 0) {
	/* eventType specific toJsonFunction */
	if (efiEventTypeTable[index].toJsonFunction != NULL) {
	    rc = efiEventTypeTable[index].toJsonFunction(efiData);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    return rc;
}

/* TSS_EFI_GetTableIndex() searches the event type table for the event handlers.

   Returns TSS_RC_NOT_IMPLEMENTED if the event type is unknown.
*/

static uint32_t TSS_EFI_GetTableIndex(size_t *index, uint32_t eventType)
{
    for (*index = 0 ;
	 *index < sizeof(efiEventTypeTable) / sizeof(EFI_EVENT_TYPE_TABLE) ;
	 (*index)++) {
	if (efiEventTypeTable[*index].eventType == eventType) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/* EV_EFI_PLATFORM_FIRMWARE_BLOB handlers */

static uint32_t TSS_EfiPlatformFirmwareBlobReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex)
{
    uint32_t rc = 0;
    UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob->BlobBase, &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob->BlobLength, &event, &eventSize);
    }
    return rc;
}

static void TSS_EfiPlatformFirmwareBlobTrace(TSST_EFIData *efiData)
{
    UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    printf("  BlobBase: %016" PRIx64 "\n", uefiPlatformFirmwareBlob->BlobBase);
    printf("  BlobLength: %016" PRIx64 "\n", uefiPlatformFirmwareBlob->BlobLength);
    return;
}

static uint32_t TSS_EfiPlatformFirmwareBlobToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    uefiPlatformFirmwareBlob = uefiPlatformFirmwareBlob; /* to silence compiler */
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG handlers */

static void TSS_EfiVariableDataInit(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData->UnicodeName = NULL;
    uefiVariableData->VariableData = NULL;
    uefiVariableData->variableDataTag = 0;
    return;
}

static void TSS_EfiVariableDataFree(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    free(uefiVariableData->UnicodeName);
    free(uefiVariableData->VariableData);
    return;
}

/* TSS_EfiVariableDataReadBuffer()

   Common code to several events.

   Validates that the event has sufficient bytes for VariableDataLength
*/

static uint32_t TSS_EfiVariableDataReadBuffer(TSST_EFIData *efiData,
					      uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(uefiVariableData->VariableName,
				  sizeof(uefiVariableData->VariableName),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiVariableData->UnicodeNameLength,
				    event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiVariableData->VariableDataLength,
				    event, eventSize);
    }
    /* sanity check the lengths since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > EFI_LENGTH_MAX/2) {
	    printf("TSS_EfiVariableDataReadBuffer: UnicodeNameLength %" PRIu64 " too large\n",
		   uefiVariableData->UnicodeNameLength);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > EFI_LENGTH_MAX) {
	    printf("TSS_EfiVariableDataReadBuffer: VariableDataLength %" PRIu64 " too large\n",
		   uefiVariableData->VariableDataLength );
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the UnicodeName array, unicode means byte array is length * 2 */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > 0) {
	    /* freed by TSS_EfiVariableDataFree */
	    uefiVariableData->UnicodeName =
		malloc((uefiVariableData->UnicodeNameLength) *2);
	    if (uefiVariableData->UnicodeName == NULL) {
		printf("TSS_EfiVariableDataReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiVariableData->UnicodeNameLength) *2);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal UnicodeName */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > 0) {
	    rc = TSS_Array_Unmarshalu(uefiVariableData->UnicodeName,
				      (uefiVariableData->UnicodeNameLength) *2,
				      event, eventSize);
	}
	else {
	    /* FIXME is UnicodeNameLength zero an error ? */
	}
    }
    /* allocate the VariableData array */
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > 0) {
	    /* freed by TSS_EfiVariableDataFree */
	    uefiVariableData->VariableData =
		malloc(uefiVariableData->VariableDataLength);
	    if (uefiVariableData->VariableData == NULL) {
		printf("TSS_EfiVariableDataReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)uefiVariableData->VariableDataLength);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal VariableData */
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > 0) {
	    rc = TSS_Array_Unmarshalu(uefiVariableData->VariableData,
				      uefiVariableData->VariableDataLength,
				      event, eventSize);
	}
	else {
	    /* FIXME is VariableDataLength zero an error ? */
	}
    }
    return rc;
}

/* common UEFI_VARIABLE_DATA trace */

static void TSS_EfiVariableDataTrace(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    guid_printf("Variable GUID", uefiVariableData->VariableName);
    wchar_printf("Variable: ", uefiVariableData->UnicodeName, uefiVariableData->UnicodeNameLength);
    printf("  VariableDataLength: %" PRIu64 "\n", uefiVariableData->VariableDataLength);
    return;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void TSS_EfiVariableDriverConfigInit(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_EfiVariableDataInit(efiData);
    uefiVariableData->variableDriverConfig.signatureListCount = 0;
    uefiVariableData->variableDriverConfig.signatureList = NULL;
    return;
}

static void TSS_EfiVariableDriverConfigFree(TSST_EFIData *efiData)
{
    uint32_t count;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    for (count = 0 ; count < uefiVariableData->variableDriverConfig.signatureListCount ; count++) {
	TSS_EfiSignatureListFree(uefiVariableData->variableDriverConfig.signatureList + count);
    }
    free(uefiVariableData->variableDriverConfig.signatureList);
    TSS_EfiVariableDataFree(efiData);
    return;
}

static uint32_t TSS_EfiVariableDriverConfigReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index; 
    pcrIndex = pcrIndex;

    /* common code for UEFI_VARIABLE_DATA */
    if (rc == 0) {
	rc = TSS_EfiVariableDataReadBuffer(efiData, &event, &eventSize);
    }
    /* map from UnicodeName to structure tag */
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    /*
      Specific code for EV_EFI_VARIABLE_DRIVER_CONFIG
    */
    /* UnicodeName = SecureBoot */
    if (rc == 0) {
	if (uefiVariableData->variableDataTag == VAR_SECUREBOOT) {
	    /* VariableDataLength 0 is treated as though its contents were zero.  Even though this
	       does not meet the UEFI spec, some platforms do this.  */
	    if ((uefiVariableData->VariableDataLength == 0) ||
		((uefiVariableData->VariableDataLength == 1) &&
		 (uefiVariableData->VariableData[0] == 0))) {
		uefiVariableData->variableDriverConfig.secureBootEnabled = 0; /* false */
	    }
	    else {
		uefiVariableData->variableDriverConfig.secureBootEnabled = 1; /* true */
	    }
	}
    }
    if (rc == 0) {
	/* unmarshal EFI_SIGNATURE_LIST's */
	if ((uefiVariableData->variableDataTag == VAR_PK)  ||
	    (uefiVariableData->variableDataTag == VAR_KEK) ||
	    (uefiVariableData->variableDataTag == VAR_DB)  ||
	    (uefiVariableData->variableDataTag == VAR_DBR) ||
	    (uefiVariableData->variableDataTag == VAR_DBT) ||
	    (uefiVariableData->variableDataTag == VAR_DBX) 
	    ) {
	    rc = TSS_EfiSignatureAllListsReadBuffer
		 (&uefiVariableData->variableDriverConfig.signatureList,
		  &uefiVariableData->variableDriverConfig.signatureListCount,
		  uefiVariableData->VariableData,
		  uefiVariableData->VariableDataLength);
	    /* trace the GUID and Var as errors */
	    if (rc != 0) {
		printf("TSS_EfiVariableDriverConfigReadBuffer: Error with tag %u\n",
		       uefiVariableData->variableDataTag);
		TSS_EfiVariableDataTrace(efiData);
	    }
	}
    }
    return rc;
}

/* TSS_EfiSignatureAllListsReadBuffer() reads a VariableData containing zero or more
   signature lists.
*/

static uint32_t TSS_EfiSignatureAllListsReadBuffer(EFI_SIGNATURE_LIST **signatureList,
						   uint32_t *signatureListCount,
						   uint8_t *VariableData, uint32_t VariableDataLength)
{
    uint32_t rc = 0;

    /* parse all the VariableData */
    while ((rc == 0) && (VariableDataLength > 0)) {
	/* malloc an additional *EFI_SIGNATURE_LIST */
	if (rc == 0) {
	    void *tmpptr;

	    (*signatureListCount)++;
	    /* freed by TSS_EfiVariableDataFree */
	    tmpptr = realloc(*signatureList,
			     sizeof(EFI_SIGNATURE_LIST) * *signatureListCount);
	    if (tmpptr != NULL) {
		*signatureList = tmpptr;
	    }
	    else {
		printf("TSS_EfiSignatureAllListsReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)sizeof(EFI_SIGNATURE_LIST) * *signatureListCount);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal this EFI_SIGNATURE_LIST */
	if (rc == 0) {
	    EFI_SIGNATURE_LIST *nextSignatureList = (*signatureList) + *signatureListCount -1;
	    TSS_EfiSignatureListInit(nextSignatureList);	/* for safe free */
	    rc = TSS_EfiSignatureListReadBuffer(nextSignatureList,
						&VariableData, &VariableDataLength);
	}
    }
    return rc;
}

static void     TSS_EfiSignatureListInit(EFI_SIGNATURE_LIST *signatureList)
{
    signatureList->SignatureHeader = NULL;
    signatureList->Signatures = NULL;
    signatureList->signaturesCount = 0;
}

static void     TSS_EfiSignatureListFree(EFI_SIGNATURE_LIST *signatureList)
{
    uint32_t count;

    free(signatureList->SignatureHeader);
    /* free all the EFI_SIGNATURE_DATA */
    for (count = 0 ; count < signatureList->signaturesCount ; count++) {
	free((signatureList->Signatures + count)->SignatureData);
    }
    free(signatureList->Signatures);
    return;
}

/* TSS_EfiSignatureListReadBuffer() reads one EFI_SIGNATURE_LIST from the event VariableData.  It
   moves the pointers since there can be more than one EFI_SIGNATURE_LIST event.
 */

static uint32_t TSS_EfiSignatureListReadBuffer(EFI_SIGNATURE_LIST *signatureList,
					       uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    void *tmpptr;			/* for realloc */
    uint32_t signatureDataLength;
    uint32_t tmpSignatureListSize;	/* because cannot change SignatureSize */

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(signatureList->SignatureType,
				  sizeof(signatureList->SignatureType),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureListSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureHeaderSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureSize, event, eventSize);
    }
    /* the SignatureSize must have at least the mandatory SignatureOwner GUID */
    if (rc == 0) {
	if (signatureList->SignatureSize >= sizeof(signatureList->Signatures->SignatureOwner)) {
	    signatureDataLength =
		signatureList->SignatureSize - sizeof(signatureList->Signatures->SignatureOwner);
	}
	else {
	    /* malformed EFI_SIGNATURE_LIST, needs at least GUID SignatureOwner */
	    printf("TSS_EfiSignatureListReadBuffer: Error in SignatureSize %u\n",
		   (unsigned int)(signatureList->SignatureSize));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* sanity check that the SignatureListSize is consistent with the SignatureSize.  Each signature
       must be the same length. */
    if (rc == 0) {
	/*  array of EFI_SIGNATURE_DATA is SignatureListSize minus header */
	tmpSignatureListSize = signatureList->SignatureListSize -
			       sizeof(signatureList->SignatureType)
			       - (sizeof(uint32_t) * 3);
	if ((tmpSignatureListSize % signatureList->SignatureSize) != 0) {
	    /* malformed EFI_SIGNATURE_LIST */
	    printf("TSS_EfiSignatureListReadBuffer: Error in SignatureSize %u\n",
		   (unsigned int)(signatureList->SignatureSize));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }

    /* FIXME handle SignatureHeaderSize, if not zero, this breaks, based on SignatureType GUID */

    /* consume this EFI_SIGNATURE_LIST */
    for ( ; (rc == 0) && (tmpSignatureListSize > 0) ;
	  tmpSignatureListSize-= signatureList->SignatureSize) {

	EFI_SIGNATURE_DATA *nextSignatureData;
	/* malloc an additional EFI_SIGNATURE_DATA */
	if (rc == 0) {

	    /* track the number of EFI_SIGNATURE_DATA in the EFI_SIGNATURE_LIST */
	    (signatureList->signaturesCount)++;
	    /* expand the array */
	    /* freed by TSS_EfiSignatureListFree */
	    tmpptr = realloc(signatureList->Signatures,
			     sizeof(EFI_SIGNATURE_DATA) * signatureList->signaturesCount);
	    if (tmpptr != NULL) {
		signatureList->Signatures = tmpptr;
		/* point to next EFI_SIGNATURE_DATA in array */
		nextSignatureData = signatureList->Signatures + signatureList->signaturesCount-1;
	    }
	    else {
		printf("TSS_EfiSignatureListReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(sizeof(EFI_SIGNATURE_DATA) * signatureList->signaturesCount));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal the signature owner */
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(nextSignatureData->SignatureOwner,
				      sizeof(signatureList->SignatureType),
				      event, eventSize);
	}
	/* malloc an EFI_SIGNATURE_DATA SignatureData */
	if (rc == 0) {
	    /* SignatureData is SignatureSize less the GUID SignatureOwner */
	    /* freed by TSS_EfiSignatureListFree */
	    tmpptr = malloc(signatureDataLength);
	    if (tmpptr != NULL) {
		nextSignatureData->SignatureData = tmpptr;
	    }
	    else {
		printf("TSS_EfiSignatureListReadBuffer: Error allocating %u bytes\n",
		       signatureDataLength);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal the signature data */
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(nextSignatureData->SignatureData,
				      signatureDataLength,
				      event, eventSize);
	}
    }
    return rc;
}

/* TSS_EfiSignatureListTrace() traces one EFI_SIGNATURE_LIST.

   There can be more than one EFI_SIGNATURE_LIST in a UEFI_VARIABLE_DATA
*/

static void     TSS_EfiSignatureListTrace(EFI_SIGNATURE_LIST *signatureList)
{
    int rc;
    size_t guidIndex;
    uint32_t count;
    X509 *x509 = NULL;
    unsigned char *tmpData = NULL; 

    guid_printf("SignatureType GUID", signatureList->SignatureType);
    printf("  SignatureListSize %u\n", signatureList->SignatureListSize);
    printf("  SignatureHeaderSize %u\n", signatureList->SignatureHeaderSize);
    /* FIXME trace SignatureHeader if not NULL */
    printf("  SignatureSize %u\n", signatureList->SignatureSize);
    printf("  signaturesCount %u\n", signatureList->signaturesCount);

    /* trace based on the guid type */
    rc = TSS_EFI_GetGuidIndex(&guidIndex, signatureList->SignatureType);
    if (rc != 0) {
	printf("  GUID unknown\n");
    }
    for (count = 0 ; (rc == 0) && (count < signatureList->signaturesCount) ; count++) {
	guid_printf("SignatureOwner GUID", (signatureList->Signatures + count)->SignatureOwner);
	switch (guidTable[guidIndex].type) {
	  case GUID_TYPE_X509_CERT:
	    /* tmp pointer because d2i moves the pointer */
	    tmpData = (signatureList->Signatures + count)->SignatureData;
	    x509 = d2i_X509(NULL,			/* freed by caller */
			    (const unsigned char **)&tmpData,
			    signatureList->SignatureSize - TSS_EFI_GUID_SIZE);
	    if (x509 != NULL) {
		X509_print_fp(stdout, x509);
	    }
	    else {
		printf("  X509 Certificate invalid\n");
	    }
	    X509_free(x509);
	    x509 = NULL;	/* for next time through loop */
	    break;
	  case  GUID_TYPE_SHA256:
	    TSS_PrintAll("    SHA-256",
			 (signatureList->Signatures + count)->SignatureData,
			 signatureList->SignatureSize - TSS_EFI_GUID_SIZE);
	    break;
	  case GUID_TYPE_UNSUPPORTED:
	  default:
	    /* FIXME add other types, need sample logs */
	    break;
	}
    }
    return;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void TSS_EfiVariableDriverConfigTrace(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;

    /* common UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableDataTrace(efiData);
    /* EV_EFI_VARIABLE_DRIVER_CONFIG trace */
    /* if the variable was SecureBoot */
    if (uefiVariableData->variableDataTag == VAR_SECUREBOOT) {
	if (uefiVariableData->variableDriverConfig.secureBootEnabled) {
	    printf("  Enabled: yes\n");
	}
	else {
	    printf("  Enabled: no\n");
	}
    }
    /* if the variable was PK, KEK, db, dbr, dbt, dbx */
    else if ((uefiVariableData->variableDataTag == VAR_PK)  ||
	     (uefiVariableData->variableDataTag == VAR_KEK) ||
	     (uefiVariableData->variableDataTag == VAR_DB)  ||
	     (uefiVariableData->variableDataTag == VAR_DBR) ||
	     (uefiVariableData->variableDataTag == VAR_DBT) ||
	     (uefiVariableData->variableDataTag == VAR_DBX)
	     ) {
	uint32_t count;
	printf("  signatureListCount: %u\n",
	       uefiVariableData->variableDriverConfig.signatureListCount);
	for (count = 0 ; count < uefiVariableData->variableDriverConfig.signatureListCount ;
	     count++) {
	    TSS_EfiSignatureListTrace(uefiVariableData->variableDriverConfig.signatureList + count);
	}
    }
    /* for currently unsupported Variables, just trace the variable */
    else {
	TSS_PrintAll("    Variable unsupported:",
		     uefiVariableData->VariableData,
		     uefiVariableData->VariableDataLength);
    }
    return;
}

static uint32_t TSS_EfiVariableDriverConfigToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData;

    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* UEFI_VARIABLE_DATA handler for event EV_EFI_VARIABLE_BOOT

   The event can either be the BootOrder (uint16_t) or a boot variable description.
 */

static void TSS_EfiVariableBootInit(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_EfiVariableDataInit(efiData);
    uefiVariableData->variableBoot.bootOrderListCount = 0;
    uefiVariableData->variableBoot.bootOrderList = NULL;
    uefiVariableData->variableBoot.bootDescription = NULL;
    uefiVariableData->variableBoot.bootPath = NULL;
    return;
}

static void TSS_EfiVariableBootFree(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    free(uefiVariableData->variableBoot.bootOrderList);
    free(uefiVariableData->variableBoot.bootDescription);
    free(uefiVariableData->variableBoot.bootPath);
    TSS_EfiVariableDataFree(efiData);
    return;
}

static uint32_t TSS_EfiVariableBootReadBuffer(TSST_EFIData *efiData,
					      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index; 
    pcrIndex = pcrIndex;

    /* common code for UEFI_VARIABLE_DATA */
    if (rc == 0) {
	rc = TSS_EfiVariableDataReadBuffer(efiData, &event, &eventSize);
    }
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    /* specific code for EV_EFI_VARIABLE_BOOT */
    /* is the UnicodeName string BootOrder */
    if (rc == 0) {
	/* unmarshal BootOrder - List of uint16_t */
	if (uefiVariableData->variableDataTag == VAR_BOOTORDER) {
	    rc = TSS_EfiBootOrderListReadBuffer(&uefiVariableData->variableBoot.bootOrderList,
						&uefiVariableData->variableBoot.bootOrderListCount,
						uefiVariableData->VariableData,
						uefiVariableData->VariableDataLength);
	}
	/* unmarshal boot path */
	else {
	    rc = TSS_EfiVariableBootPathReadBuffer(&uefiVariableData->variableBoot.isBootEnabled,
						   &uefiVariableData->variableBoot.bootDescription,
						   &uefiVariableData->variableBoot.bootPath,
						   uefiVariableData->VariableData,
						   uefiVariableData->VariableDataLength);
	}
	/* trace the GUID and Var as errors */
	if (rc != 0) {
	    printf("TSS_EfiVariableBootReadBuffer: Error with tag %u\n",
		   uefiVariableData->variableDataTag);
	    TSS_EfiVariableDataTrace(efiData);
	}
    }
    return rc;
}

/* TSS_EfiBootOrderListReadBuffer() unmarshals the BootOrder variable data into an array of uint16_t
*/

static uint32_t TSS_EfiBootOrderListReadBuffer(uint16_t **bootOrderList,
					       uint32_t *bootOrderListCount,
					       uint8_t *VariableData, uint32_t VariableDataLength)
{
    uint32_t rc = 0;
    uint32_t count;

    if (rc == 0) {
	if ((VariableDataLength % 2) == 0) {
	    *bootOrderListCount = VariableDataLength / 2;
	}
	else {
	    printf("TSS_EfiBootOrderListReadBuffer: Error in VariableDataLength %u\n",
		   VariableDataLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* malloc the array of boot order uint16_t */
    if (rc == 0) {
        /* freed by TSS_EfiVariableDataInit */
	*bootOrderList = malloc(*bootOrderListCount * sizeof(uint16_t));
	if (*bootOrderList == NULL) {
	    printf("TSS_EfiBootOrderListReadBuffer: Error allocating %u bytes\n",
		   (unsigned int)(*bootOrderListCount * sizeof(uint16_t)));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* iterate and build the bootOrderList array of uint16_t */
    for (count = 0 ; (rc == 0) && (count < *bootOrderListCount) ; count++) {
	uint16_t *nextBootOrderList = *bootOrderList + count;
	rc = TSS_UINT16LE_Unmarshal(nextBootOrderList, 
				    &VariableData, &VariableDataLength);
    }
    return rc;
}

static uint32_t TSS_EfiVariableBootPathReadBuffer(uint32_t *isBootEnabled,
						  char **bootDescription,
						  char **bootPath,
						  void *VariableData, uint64_t VariableDataLength)
{
    uint32_t rc = 0;
#ifdef HAVE_EFIBOOT_H
    int isValid;
    efi_load_option *loadOption = VariableData;
    const char *description = NULL;
    efidp efidp;
    uint16_t pathlen;

    /* int efi_loadopt_is_valid(efi_load_option *opt, size_t size) */
    if (rc == 0) {
	/* This fails on Supermicro https://github.com/rhboot/efivar/issues/163 */
	isValid = efi_loadopt_is_valid(loadOption, VariableDataLength);
	if (isValid) {
	    /* uint32_t efi_loadopt_attrs(efi_load_option *opt) */
	    *isBootEnabled = efi_loadopt_attrs(loadOption) & 1;
	}
	else {
	    /* invalid load option */
	    printf("TSS_EfiVariableBootPathReadBuffer: Error in efi_loadopt_is_valid\n");
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    /* const unsigned char * efi_loadopt_desc(efi_load_option *opt, ssize_t limit)
     */
    if (rc == 0) {
	description = (const char *)efi_loadopt_desc(loadOption, VariableDataLength);
	if (description == NULL) {
	    printf("TSS_EfiVariableBootPathReadBuffer: Error in efi_loadopt_desc\n");
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    if (rc == 0) {
	size_t descriptionLength = strlen(description);
	/* freed by TSS_EfiVariableDataFree */
	*bootDescription = malloc(descriptionLength +1);
	if (*bootDescription != NULL) {
	    strcpy(*bootDescription, (char *)description);
	}
	else {
	    printf("TSS_EfiVariableBootPathReadBuffer: Error allocating %u bytes\n",
		   (unsigned int)descriptionLength +1);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* efidp efi_loadopt_path(efi_load_option *opt, ssize_t limit) */
    /* uint16_t efi_loadopt_pathlen(efi_load_option *opt, ssize_t limit) */
    if (rc == 0) {
	efidp = efi_loadopt_path(loadOption, VariableDataLength);
	pathlen = efi_loadopt_pathlen(loadOption, VariableDataLength);
    }
    if (rc == 0) {
	rc = TSS_EfiFormatDevicePath(bootPath,
				     (uint8_t *)efidp,
				     pathlen);
    }
#else
    isBootEnabled = isBootEnabled;
    bootDescription = bootDescription;
    bootPath = bootPath;
    VariableData = VariableData;
    VariableDataLength = VariableDataLength;
#endif	/* HAVE_EFIBOOT_H */
    return rc;
}

static void TSS_EfiVariableBootTrace(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uint32_t count;

    /* common UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableDataTrace(efiData);
    /* is the UnicodeName string BootOrder */
    if (uefiVariableData->variableDataTag == VAR_BOOTORDER) {
	printf("  Boot Order: ");
	for (count = 0 ; count < uefiVariableData->variableBoot.bootOrderListCount ; count++) {
            printf("Boot%04x ", *(uefiVariableData->variableBoot.bootOrderList + count));
	}
	printf("\n");
    }
    else {
	printf("  Enabled: %s\n", uefiVariableData->variableBoot.isBootEnabled ? "Yes" : "No");
	printf("  Description: %s\n", uefiVariableData->variableBoot.bootDescription);
	printf("  Path: %s\n", uefiVariableData->variableBoot.bootPath);
    }
    return;
}

static uint32_t TSS_EfiVariableBootToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData;

    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_VARIABLE_AUTHORITY */

static void     TSS_EfiVariableAuthorityInit(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_EfiVariableDataInit(efiData);
    uefiVariableData->authoritySignatureData.SignatureData = NULL;
    return;
}

static void     TSS_EfiVariableAuthorityFree(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    free(uefiVariableData->authoritySignatureData.SignatureData);
    TSS_EfiVariableDataFree(efiData);
    return;
}

static uint32_t TSS_EfiVariableAuthorityReadBuffer(TSST_EFIData *efiData,
						   uint8_t *event, uint32_t eventSize,
						   uint32_t pcrIndex)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index; 
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_EfiVariableDataReadBuffer(efiData,
					   &event, &eventSize);
    }
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    if (rc == 0) {
	TSS_AUTHORITY_SIGNATURE_DATA *authoritySignatureData =
	    &uefiVariableData->authoritySignatureData;
	/* tmp because unmarshal moves pointers */
	uint8_t *tmpVarData = uefiVariableData->VariableData;
	uint32_t tmpVarDataLength = uefiVariableData->VariableDataLength;

	/* db has an owner, shim does not */
	if (uefiVariableData->variableDataTag == VAR_DB) {
	    /* unmarshal the signature owner */
	    if (rc == 0) {
		rc = TSS_Array_Unmarshalu(authoritySignatureData->SignatureOwner,
					  sizeof(authoritySignatureData->SignatureOwner),
					  &tmpVarData, &tmpVarDataLength);
	    }
	}
	/* intentional fall through for DB */
	if ((uefiVariableData->variableDataTag == VAR_DB) ||
	    (uefiVariableData->variableDataTag == VAR_SHIM) ||
	    (uefiVariableData->variableDataTag == VAR_MOKLIST)) {

	    /* assume the rest of the event is the certificate since there is no SignatureSize
	       field */
	    if (rc == 0) {
		authoritySignatureData->SignatureLength = tmpVarDataLength;
		authoritySignatureData->SignatureData =
		    malloc(authoritySignatureData->SignatureLength);
		if (authoritySignatureData->SignatureData == NULL) {
		    printf("TSS_EfiVariableAuthorityReadBuffer: Error allocating %u bytes\n",
			   (unsigned int)authoritySignatureData->SignatureLength);
		    rc = TSS_RC_OUT_OF_MEMORY;
		}
	    }
	    /* unmarshal the signature data */
	    if (rc == 0) {
		rc = TSS_Array_Unmarshalu(authoritySignatureData->SignatureData,
					  authoritySignatureData->SignatureLength,
					  &tmpVarData, &tmpVarDataLength);
	    }
	    /* trace the GUID and Var as errors */
	    if (rc != 0) {
		printf("TSS_EfiVariableAuthorityReadBuffer: Error with tag %u\n",
		       uefiVariableData->variableDataTag);
		TSS_EfiVariableDataTrace(efiData);
	    }
	    /* FIXME sanity check for all consumed */
	    /* tmpVarDataLength should be zero.  This is underspecified in PTP */
	}
    }
    return rc;
}

static void TSS_EfiVariableAuthorityTrace(TSST_EFIData *efiData)
{
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_AUTHORITY_SIGNATURE_DATA *authoritySignatureData =
	&uefiVariableData->authoritySignatureData;
    X509 *x509 = NULL;
    unsigned char *tmpData = NULL; 

    /* common UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableDataTrace(efiData);
    /* not part of UEFI structure */
    printf("  SignatureLength: %u\n", authoritySignatureData->SignatureLength);
    /* db has an owner, shim does not */
    if (uefiVariableData->variableDataTag == VAR_DB) {
	guid_printf("SignatureOwner GUID", authoritySignatureData->SignatureOwner);
    }
    if ((uefiVariableData->variableDataTag == VAR_DB) ||
	(uefiVariableData->variableDataTag == VAR_SHIM) ||
	(uefiVariableData->variableDataTag == VAR_MOKLIST)) {

	tmpData = authoritySignatureData->SignatureData;
	x509 = d2i_X509(NULL,			/* freed by caller */
			(const unsigned char **)&tmpData,
			authoritySignatureData->SignatureLength);
	if (x509 != NULL) {
	    X509_print_fp(stdout, x509);
	}
	else {
	    printf("  X509 Certificate invalid\n");
	}
	X509_free(x509);
	x509 = NULL;
    }
    return;
}

static uint32_t TSS_EfiVariableAuthorityToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData ;

    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER handler

   The event field MUST contain a UEFI_IMAGE_LOAD_EVENT structure.
*/

static void TSS_EfiBootServicesInit(TSST_EFIData *efiData)
{
    UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    uefiImageLoadEvent->DevicePath = NULL;
    uefiImageLoadEvent->Path = NULL;
    return;
}

static void TSS_EfiBootServicesFree(TSST_EFIData *efiData)
{
    UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    free(uefiImageLoadEvent->DevicePath);
    free(uefiImageLoadEvent->Path);
    return;
}

static uint32_t TSS_EfiBootServicesReadBuffer(TSST_EFIData *efiData,
					      uint8_t *event, uint32_t eventSize,
					      uint32_t pcrIndex)
{
    uint32_t rc = 0;
    UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLocationInMemory,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLengthInMemory,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLinkTimeAddress,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->LengthOfDevicePath,
				    &event, &eventSize);
    }
    /* sanity check the length since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > EFI_LENGTH_MAX) {
	    printf("TSS_EfiBootServicesReadBuffer: LengthOfDevicePath %" PRIu64 " too large\n",
		   uefiImageLoadEvent->LengthOfDevicePath);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the DevicePath array */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > 0) {
	    /* freed by TSS_EfiBootServicesFree */
	    uefiImageLoadEvent->DevicePath = malloc(uefiImageLoadEvent->LengthOfDevicePath);
	    if (uefiImageLoadEvent->DevicePath == NULL) {
		printf("TSS_EfiBootServicesReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiImageLoadEvent->LengthOfDevicePath));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal DevicePath */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > 0) {
	    rc = TSS_Array_Unmarshalu(uefiImageLoadEvent->DevicePath,
				      uefiImageLoadEvent->LengthOfDevicePath,
				      &event, &eventSize);
	}
	else {
	    /* FIXME is LengthOfDevicePath zero an error ? */
	}
    }
#if HAVE_EFIBOOT_H
    /* format path */
    if (rc == 0) {
	rc = TSS_EfiFormatDevicePath(&uefiImageLoadEvent->Path,
				     uefiImageLoadEvent->DevicePath,
				     uefiImageLoadEvent->LengthOfDevicePath);
    }
#endif /* HAVE_EFIBOOT_H */
    return rc;
}

static void TSS_EfiBootServicesTrace(TSST_EFIData *efiData)
{
    UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    printf("  Image location in memory: %016" PRIx64 "\n", uefiImageLoadEvent->ImageLocationInMemory);
    printf("  Image length in memory: %" PRIu64 "\n", uefiImageLoadEvent->ImageLengthInMemory);
    printf("  Image link time address: %016" PRIx64 "\n", uefiImageLoadEvent->ImageLinkTimeAddress);
    printf("  Path: %s\n", uefiImageLoadEvent->Path);
    return;
}

static uint32_t TSS_EfiBootServicesToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    uefiImageLoadEvent  = uefiImageLoadEvent;
    return rc;
}

/* EV_EFI_GPT_EVENT */

static void TSS_EfiGptEventInit(TSST_EFIData *efiData)
{
    UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    uefiGptData->Partitions = NULL;
    uefiGptData->UEFIPartitionHeader.Reserved2 = NULL;
    return;
}

static void TSS_EfiGptEventFree(TSST_EFIData *efiData)
{
    UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    free(uefiGptData->Partitions);
    free(uefiGptData->UEFIPartitionHeader.Reserved2);
    return;
}

static uint32_t TSS_EfiGptEventReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize,
					  uint32_t pcrIndex)
{
    uint32_t rc = 0;
    uint64_t partitionCount;
    UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader = &(uefiGptData->UEFIPartitionHeader);

    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_EfiPartitionHeaderReadBuffer(efiPartitionHeader,
					      &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiGptData->NumberOfPartitions, &event, &eventSize);
    }
    if (rc == 0) {
	if (uefiGptData->NumberOfPartitions > EFI_LENGTH_MAX) {
	    printf("TSS_EfiVariableDataReadBuffer: VariableDataLength %" PRIu64 " too large\n",
		   uefiGptData->NumberOfPartitions);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    if (rc == 0) {
	if (uefiGptData->NumberOfPartitions > 0) {
	    /* freed by TSS_EfiGptEventFree */
	    uefiGptData->Partitions =
		malloc(uefiGptData->NumberOfPartitions * sizeof(UEFI_PARTITION_ENTRY));
	    if (uefiGptData->Partitions == NULL) {
		printf("TSS_EfiGptEventReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)
		       (uefiGptData->NumberOfPartitions * sizeof(UEFI_PARTITION_ENTRY)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    for (partitionCount = 0 ;
	 (rc == 0) && (partitionCount < uefiGptData->NumberOfPartitions) ;
	 partitionCount++) {

	UEFI_PARTITION_ENTRY *entry = uefiGptData->Partitions + partitionCount;
	if (rc == 0) {
	    rc = TSS_EfiPartitionEntryReadBuffer(entry, &event, &eventSize);
	}
    }
    return rc;
}

static uint32_t TSS_EfiPartitionHeaderReadBuffer(UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader,
						 uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    uint32_t startEventSize = *eventSize; /* track what was unmarshaled, excluding reserved */

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->Signature, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->Revision, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->HeaderSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->HeaderCRC32, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->Reserved1, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->MyLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->AlternateLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->FirstUsableLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->LastUsableLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(efiPartitionHeader->DiskGUID,
				  sizeof(efiPartitionHeader->DiskGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->PartitionEntryLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->NumberOfPartitionEntries, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->SizeOfPartitionEntry, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->PartitionEntryArrayCRC32, event, eventSize);
    }
    /* skip the reserved area for now */
    if (rc == 0) {
	uint32_t endEventSize = *eventSize;
	uint32_t usedBytes = startEventSize - endEventSize;  		/* used in the header */
	uint32_t skipBytes = efiPartitionHeader->HeaderSize - usedBytes; /* the reserved field */
	if (skipBytes <= *eventSize) {		/* bounds check */
	    /* skip unused bytes that are reserved */
	    *event += skipBytes;
	    *eventSize -= skipBytes;
	}
	else {	/* HeaderSize inconsistent with eventSize */
	    rc = TPM_RC_INSUFFICIENT;
	}
    }
    return rc;
}

static uint32_t TSS_EfiPartitionEntryReadBuffer(UEFI_PARTITION_ENTRY *entry,
						uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->PartitionTypeGUID,
				  sizeof(entry->PartitionTypeGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->UniquePartitionGUID,
				  sizeof(entry->UniquePartitionGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->StartingLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->EndingLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->Attributes, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->PartitionName,
				  sizeof(entry->PartitionName),
				  event, eventSize);
    }
    return rc;
}

static void TSS_EfiGptEventTrace(TSST_EFIData *efiData)
{
    UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader = &(uefiGptData->UEFIPartitionHeader);
    uint64_t partitionCount;

    TSS_EfiPartitionHeaderTrace(efiPartitionHeader);
    printf("  Number of Partitions: %" PRIu64 "\n\n", uefiGptData->NumberOfPartitions);
    for (partitionCount = 0 ;
	 partitionCount < uefiGptData->NumberOfPartitions ;
	 partitionCount++) {

	UEFI_PARTITION_ENTRY *entry = uefiGptData->Partitions + partitionCount;
	TSS_EfiPartitionEntryTrace(entry);
    }
    return;
}

static void TSS_EfiPartitionHeaderTrace(UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader)
{
    printf("  Signature %016" PRIx64 "\n", efiPartitionHeader->Signature);
    printf("  Revision %08x\n", efiPartitionHeader->Revision);
    printf("  HeaderSize %u\n", efiPartitionHeader->HeaderSize);
    printf("  HeaderCRC32 %08x\n", efiPartitionHeader->HeaderCRC32);
    printf("  Reserved1 %u\n", efiPartitionHeader->Reserved1);
    printf("  MyLBA %016" PRIx64 "\n", efiPartitionHeader->MyLBA);
    printf("  AlternateLBA %016" PRIx64 "\n", efiPartitionHeader->AlternateLBA);
    printf("  FirstUsableLBA %016" PRIx64 "\n", efiPartitionHeader->FirstUsableLBA);
    printf("  LastUsableLBA %016" PRIx64 "\n", efiPartitionHeader->LastUsableLBA);
    guid_printf("DiskGUID", efiPartitionHeader->DiskGUID);
    printf("  PartitionEntryLBA %016" PRIx64 "\n", efiPartitionHeader->PartitionEntryLBA);
    printf("  NumberOfPartitionEntries %u\n", efiPartitionHeader->NumberOfPartitionEntries);
    printf("  SizeOfPartitionEntry %u\n", efiPartitionHeader->SizeOfPartitionEntry);
    printf("  PartitionEntryArrayCRC32 %08x\n", efiPartitionHeader->PartitionEntryArrayCRC32);
    return;
}

static void TSS_EfiPartitionEntryTrace(UEFI_PARTITION_ENTRY *entry)
{
    guid_printf("  PartitionTypeGUID", entry->PartitionTypeGUID);
    guid_printf("  UniquePartitionGUID", entry->UniquePartitionGUID);
    printf("    StartingLBA %016" PRIx64 "\n", entry->StartingLBA);
    printf("    EndingLBA %016" PRIx64 "\n",  entry->EndingLBA);
    printf("    Attributes %016" PRIx64 "\n", entry->Attributes);
    printf("    PartitionName %.*s\n", (int)sizeof(entry->PartitionName), entry->PartitionName);
    printf("\n");
    return;
}


static uint32_t TSS_EfiGptEventToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    uefiGptData = uefiGptData;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_VERSION
   EV_POST_CODE
*/

static void TSS_Efi4bBufferInit(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer->buffer = NULL;
    return;
}

static void TSS_Efi4bBufferFree(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    free(tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_Efi4bBufferReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	tss4bBuffer->size = eventSize;
	/* allocate the array*/
	if (tss4bBuffer->size > 0) {
	    /* freed by TSS_Efi4bBufferFree */
	    tss4bBuffer->buffer = malloc(tss4bBuffer->size);
	    if (tss4bBuffer->buffer == NULL) {
		printf("TSS_Efi4bBufferReadBuffer: Error allocating %u bytes\n",
		       tss4bBuffer->size);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal UnicodeName */
    if (rc == 0) {
	if (tss4bBuffer->size > 0) {
	    rc = TSS_Array_Unmarshalu(tss4bBuffer->buffer, tss4bBuffer->size,
				      &event, &eventSize);
	}
	else {
	    /* FIXME is zero an error ? */
	}
    }
    return rc;
}

/* EV_COMPACT_HASH */

static void     TSS_EfiCompactHashTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    /* PCR 6 event holds a string */
    if (efiData->pcrIndex == 6) {
	printf("  Compact Hash: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    }
    else {
	TSS_PrintAll("    Compact Hash",
		     tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

static uint32_t TSS_EfiCompactHashToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;

    if (rc == 0) {
    }
    return rc;
}

/* EV_IPL */

static void     TSS_EfiIplTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    /* unspecified, apparently holds a string */
    printf("  IPL: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiIplToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;

    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_VERSION can be either a UCS-2 or a GUID. */

static void TSS_EfiCrtmVersionTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    int isUCS2 = 1;
    uint32_t i;

    /* non-deterministic, guess whether this is a UCS-2 string or a GUID */
    /* GUID is always 16 bytes */
    if (tss4bBuffer->size == TSS_EFI_GUID_SIZE) {
	for (i = 1 ; (i < tss4bBuffer->size) && (isUCS2) ; i+=2) {
	    if (tss4bBuffer->buffer[i] != 0x00) {
		isUCS2 = 0;	/* UCS-2 typically has all odd bytes 0 */
	    }
	}
    }
    /* not 16 bytes falls through to isUCS2 true */
    if (isUCS2) {
	wchar_printf("CRTM Version: ", tss4bBuffer->buffer, ((tss4bBuffer->size) / 2) -1);
    }
    else {
	guid_printf("CRTM Version GUID", tss4bBuffer->buffer);
    }
    return;
}

static uint32_t TSS_EfiCrtmVersionToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_CONTENTS */

static void TSS_EfiCrtmContentsTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf("  CRTM Contents: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiCrtmContentsToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_ACTION */

static void TSS_EfiActionTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf("  EFI Action: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiActionToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_POST_CODE

   FIXME This event sometimes measures a 16 byte non-printable string.  What is is?
*/

static uint32_t TSS_EfiCharReadBuffer(TSST_EFIData *efiData,
				      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_Efi4bBufferReadBuffer(efiData, event, eventSize, pcrIndex);
    }
    /* FIXME is zero length an error ? */
    /* TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer; */
   return rc;
}

static void TSS_EfiCharTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf(" %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiCharToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_SEPARATOR */

static void TSS_EfiSeparatorTrace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;

    /* By observation, the separator for thses PCRs seem to be ascii */
    if ((efiData->pcrIndex == 12) ||
	(efiData->pcrIndex == 13) ||
	(efiData->pcrIndex == 14)) {
	printf("  Separator: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    }
    else {
	TSS_PrintAll("  Separator",
		     tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

static uint32_t TSS_EfiSeparatorToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_HANDOFF_TABLES */

static void TSS_EfiHandoffTablesInit(TSST_EFIData *efiData)
{
    UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    uefiHandoffTablePointers->TableEntry = NULL;
    return;
}

static void TSS_EfiHandoffTablesFree(TSST_EFIData *efiData)
{
    UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    free(uefiHandoffTablePointers->TableEntry);
    return;
}

static uint32_t TSS_EfiHandoffTablesReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    uint64_t tableCount;
    UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiHandoffTablePointers->NumberOfTables, &event, &eventSize);
    }
    /* sanity check the lengths since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiHandoffTablePointers->NumberOfTables >
	    EFI_LENGTH_MAX/sizeof(EFI_CONFIGURATION_TABLE)) {
	    printf("TSS_EfiHandoffTablesReadBuffer: NumberOfTables %" PRIu64 " too large\n",
		   uefiHandoffTablePointers->NumberOfTables);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the EFI_CONFIGURATION_TABLE list */
    if (rc == 0) {
	if (uefiHandoffTablePointers->NumberOfTables > 0) {
	    /* freed by TSS_EfiHandoffTablesFree */
	    uefiHandoffTablePointers->TableEntry =
		malloc(uefiHandoffTablePointers->NumberOfTables * sizeof(EFI_CONFIGURATION_TABLE));
	    if (uefiHandoffTablePointers->TableEntry == NULL) {
		printf("TSS_EfiHandoffTablesReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)
		       (uefiHandoffTablePointers->NumberOfTables * sizeof(EFI_CONFIGURATION_TABLE)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal Tables */
    for (tableCount = 0 ;
	 (rc == 0) && (tableCount < uefiHandoffTablePointers->NumberOfTables) ;
	 tableCount++) {

	EFI_CONFIGURATION_TABLE *table = uefiHandoffTablePointers->TableEntry + tableCount;
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(table->VendorGuid,
				      sizeof(table->VendorGuid),
				      &event, &eventSize);
	}
	if (rc == 0) {
	    rc = TSS_UINT64LE_Unmarshal(&table->VendorTable, &event, &eventSize);
	}
    }
    return rc;
}

static void     TSS_EfiHandoffTablesTrace(TSST_EFIData *efiData)
{
    uint64_t tableCount;
    UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;

    printf("  NumberOfTables: %016" PRIx64 "\n", uefiHandoffTablePointers->NumberOfTables);
    for (tableCount = 0 ; tableCount < uefiHandoffTablePointers->NumberOfTables ; tableCount++) {
	EFI_CONFIGURATION_TABLE *table = uefiHandoffTablePointers->TableEntry + tableCount;
	guid_printf("VendorGuid", table->VendorGuid);
	printf("  VendorTable: %016" PRIx64 "\n", table->VendorTable);
    }
    return;
}

static uint32_t TSS_EfiHandoffTablesToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    uefiHandoffTablePointers  =uefiHandoffTablePointers;
    if (rc == 0) {
    }
    return rc;
}


/* TSS_EFI_GetGuidIndex() gets the index into the GUID table for the GUID array guidBin

   Returns TSS_RC_NOT_IMPLEMENTED for an unimplemeted GUID.
*/

static uint32_t TSS_EFI_GetGuidIndex(size_t *index, const uint8_t *guidBin)
{
    for (*index = 0 ;
	 *index < sizeof(guidTable) / sizeof(GUID_TABLE) ;
	 (*index)++) {
	if (memcmp(guidTable[*index].guidBin, guidBin, 16) == 0) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/* TSS_EFI_GetTagIndex() gets the index into the tag table for the name.

   If the name does't match, returns index 0, which is the unknown name.
*/

static void TSS_EFI_GetNameIndex(size_t *index,
				 const uint8_t *name,
				 uint64_t nameLength)	/* half the total bytes in array */
{
    int m1,m2;
    for (*index = 0 ;
	 *index < sizeof(tagTable) / sizeof(TAG_TABLE)  ;
	 (*index)++) {

	m1 = (nameLength * 2) == tagTable[*index].nameLength;			/* length match */
	m2 = memcmp(name, tagTable[*index].name, (nameLength * 2)) == 0;	/* string match */
	if (m1 & m2) {
	    return;
	}
    }
    *index = 0;		/* no match, unknown */
    return;
}

/* guid_printf() traces the input GUID, first as hexacsii and then as text.

   It prepends msg to ther hexascii trace.  msg must not be NULL but can be "".
*/

static void guid_printf(const char *msg, uint8_t *v_guid)
{
#if HAVE_EFIBOOT_H
    int rc;
    efi_guid_t *guid = (efi_guid_t *)v_guid;
    char *guid_str = NULL;
    size_t index;

    /* allocates a suitable string and populates it with string representation of a UEFI GUID. */
    rc = efi_guid_to_str(guid, &guid_str);	/* freed @1 */
    if (rc < 0) {
        printf("  %s: <invalid guid>", msg);
        return;
    }
    printf("  %s: %s\n", msg, guid_str);
    /* trace the GUID as text */
    rc = TSS_EFI_GetGuidIndex(&index, v_guid);
    if (rc == 0) {
	printf("    %s\n", guidTable[index].guidText);
    }
    /* if the GUID is unknown, don't print any text, just the hexascii guid */
    free(guid_str);	/* @1 */
#else	/* if EFI package is not installed, trace as hex */
    printf("  %s: ", msg);
    TSS_PrintAll("", v_guid, TSS_EFI_GUID_SIZE);
#endif /* HAVE_EFIBOOT_H */
    return;
}


/* Print UCS-2 character string.

   length is number of characters, which is half the number of bytes in wchar
   wchar is a uc16 array to be printed, not including an extra nul terminator

   It prepends msg to ther hexascii trace.  msg must not be NULL but can be "".
*/

static void wchar_printf(const char *msg, void *wchar, uint64_t length)
{
    uint32_t i;
    uint16_t *ptr = wchar;

    /*
     * this is necessary because UEFI uses UCS-2, which is a two byte
     * wide char.  Most linux tools use UC32, which is a four byte
     * wide char, so we can't simply treat UEFI strings as arrays of
     * wchar_t
     */
    printf("  %s", msg);
    for (i = 0; i < length ; i++) {
        wchar_t c = (wchar_t)ptr[i];	/* FIXME alignment issues */
        printf("%lc", c);
    }
    printf("\n");
    return;
}

#ifdef HAVE_EFIBOOT_H

/* ssize_t efidp_format_device_path(char *buf, size_t size, const_efidp dp, ssize_t limit); */

/* TSS_EfiFormatDevicePath() runs efidp_format_device_path twice, first to get the size, then to get
   the path

   path must be freed by the caller
*/

static uint32_t TSS_EfiFormatDevicePath(char **path,
					uint8_t *devicePath,
					uint16_t pathlen)
{
    uint32_t rc = 0;
    ssize_t ssrc;	/* return code */
    size_t pathLength;
    efidp efiDevicePath = (efidp)devicePath;

    if (pathlen > 0) {
	/* ssize_t efidp_format_device_path(char *buf, size_t size, const_efidp dp, ssize_t
	   limit); */
	if (rc == 0) {
	    /* returns the length, negative is error */
	    ssrc = efidp_format_device_path(NULL,		/* buffer */
					    0,			/* length */
					    efiDevicePath,	/* const_efidp */
					    pathlen);		/* length */
	    if (ssrc < 0) {
		printf("TSS_EfiVariableBootPathReadBuffer: Error in efidp_format_device_path\n");
		rc = TSS_RC_BAD_PROPERTY;
	    }
	}
	if (rc == 0) {
	    pathLength = ssrc + 1;	/* +1 for NUL terminator? */
	    *path = malloc(pathLength);	/* freed by caller */
	    if (*path == NULL) {
		printf("TSS_EfiFormatDevicePath: Error allocating %u bytes\n",
		       (unsigned int)pathLength);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    ssrc = efidp_format_device_path(*path, pathLength,
					    efiDevicePath, pathlen);
	    if (ssrc < 0) {
		printf("TSS_EfiVariableBootPathReadBuffer: Error in efidp_format_device_path\n");
		rc = TSS_RC_BAD_PROPERTY;
	    }
	}
    }
    else {	/* pathlen 0 is a bug in the event logging */
	if (rc == 0) {
	    *path = malloc(1);
	    if (*path == NULL) {
		printf("TSS_EfiFormatDevicePath: Error allocating %u byte\n", 1);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* return an empty path */
	if (rc == 0) {
	    *path[0] = '\0';
	}
    }
    return rc;
}

#endif	/*  HAVE_EFIBOOT_H */
