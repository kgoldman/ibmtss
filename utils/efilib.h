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
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef EFILIB_H
#define EFILIB_H

#include <inttypes.h>

#include <efivar/efiboot.h>

/* EFI_SIGNATURE_DATA from UEFI spec */

typedef struct {
    uint8_t   SignatureOwner[sizeof(efi_guid_t)];
    uint8_t  *SignatureData;
} EFI_SIGNATURE_DATA;

typedef struct {
    uint8_t   SignatureOwner[sizeof(efi_guid_t)];
    uint8_t  *SignatureData;
    /* since EV_EFI_VARIABLE_AUTHORITY doesn't have an exlicit length */
    uint32_t  SignatureLength;
} TSS_AUTHORITY_SIGNATURE_DATA;

/* UEFI_VARIABLE_DATA VariableData contents for EV_EFI_VARIABLE_DRIVER_CONFIG and guid for PK KEK db
   dbx dbt dbr */

typedef struct {
    uint8_t  SignatureType[sizeof(efi_guid_t)];
    uint32_t SignatureListSize;		/* includes the header */
    uint32_t SignatureHeaderSize;
    uint32_t SignatureSize;		/* size of each signature */
    /* Header before the array of signatures. The format of this header is specified by the
       SignatureType. */
    uint8_t  *SignatureHeader;		/* [SignatureHeaderSize] */
    EFI_SIGNATURE_DATA *Signatures;	/* Array of EFI_SIGNATURE_DATA */
    /* NOTE This is not part of EFI structure */
    uint32_t signaturesCount;
} EFI_SIGNATURE_LIST;

/* UEFI_VARIABLE_DATA VariableData contents for EV_EFI_VARIABLE_DRIVER_CONFIG */
typedef struct {
    int secureBootEnabled;	/* boolean */
    /* EV_EFI_VARIABLE_DRIVER_CONFIG PK KEK db dbx dbt dbr */
    uint32_t signatureListCount;
    EFI_SIGNATURE_LIST *signatureList;
} TSS_VARIABLE_DRIVER_CONFIG;

/* EV_EFI_GPT_EVENT */

/* This structure contains a GUID Partition Table, and is defined in the TGC PC
   Client Platform Firmware Profile Specification Revision 1.04 Section 9.4.
   Its structure members are defined in the UEFI Specification Version 2.8
   Section 5.3 Table 21.
*/

typedef struct {
    uint64_t Signature;	/* "EFI PART", encoded as the 64-bit constant 0x5452415020494645 */
    uint32_t Revision;	/* This header is version 1.0, so the correct value is 0x00010000 */
    uint32_t HeaderSize;
    uint32_t HeaderCRC32;
    uint32_t Reserved1;	/* must be zero */
    uint64_t MyLBA;
    uint64_t AlternateLBA;
    uint64_t FirstUsableLBA;
    uint64_t LastUsableLBA;
    uint8_t  DiskGUID[sizeof(efi_guid_t)];
    uint64_t PartitionEntryLBA;
    uint32_t NumberOfPartitionEntries;
    uint32_t SizeOfPartitionEntry;
    uint32_t PartitionEntryArrayCRC32;
    uint8_t  *Reserved2;
} UEFI_PARTITION_TABLE_HEADER;

/* GPT Parition Table Attributes UEFI Table 24 */

#define UEFI_REQUIRED_PARTITION 0x0000000000000001
#define UEFI_NO_BLOCK_IO	0x0000000000000002
#define UEFI_LEGACY_BIOS	0x0000000000000003

/* UEFI Specification Version 2.8 Section 5.3 Table 22 */

typedef struct {
    uint8_t PartitionTypeGUID[sizeof(efi_guid_t)];
    uint8_t UniquePartitionGUID[sizeof(efi_guid_t)];
    uint64_t StartingLBA;
    uint64_t EndingLBA;
    uint64_t Attributes;	/* UEFI Table 24 */
    uint8_t PartitionName[72]; 	/* Null-terminated string containing name of the partition */
} UEFI_PARTITION_ENTRY;

/* EV_EFI_GPT_EVENT */

typedef struct  {
    UEFI_PARTITION_TABLE_HEADER UEFIPartitionHeader;
    uint64_t NumberOfPartitions;
    UEFI_PARTITION_ENTRY *Partitions;
} UEFI_GPT_DATA;

/* EV_COMPACT_HASH is currently just an unstructured buffer and size */

/* EV_EFI_VARIABLE_BOOT */

typedef struct  {
    /* EV_EFI_VARIABLE_BOOT BootOrder */
    uint32_t bootOrderListCount;
    uint16_t *bootOrderList;
    /* EV_EFI_VARIABLE_BOOT Boot Path */
    uint32_t isBootEnabled;
    char *bootDescription;
    char *bootPath;
} TSS_VARIABLE_BOOT;

/* This structure is used to designate the measurement of UEFI variables. The
   structure is defined in the TGC PC Client Platform Firmware Profile Specification
   Revision 1.04 Section 9.2.6. */

typedef struct {
    uint8_t VariableName[sizeof(efi_guid_t)];	/* FIXME from UEFI spec, efi_guid_t, 128 bits */
    uint64_t UnicodeNameLength;
    uint64_t VariableDataLength;
    uint8_t *UnicodeName;
    uint8_t *VariableData;
    /* NOTE: The following are not part of UEFI_VARIABLE_DATA structure */
    int variableDataTag;	/* tag for following union */
    /* subclasses */
    union {
	/* EV_EFI_VARIABLE_DRIVER_CONFIG subclass for tag PK KEK db dbx dbr dbt SecureBoot
	   secureboot */
	TSS_VARIABLE_DRIVER_CONFIG variableDriverConfig;
	/* EV_EFI_VARIABLE_BOOT subclass for tag VAR_BOOTORDER */
	TSS_VARIABLE_BOOT variableBoot;
	/* EV_EFI_VARIABLE_AUTHORITY */
	TSS_AUTHORITY_SIGNATURE_DATA authoritySignatureData;
    };
} UEFI_VARIABLE_DATA;

typedef uint64_t UEFI_PHYSICAL_ADDRESS;

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

typedef struct {
    UEFI_PHYSICAL_ADDRESS   BlobBase;
    uint64_t 		    BlobLength;
} UEFI_PLATFORM_FIRMWARE_BLOB;

/* EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER */

typedef struct {
    UEFI_PHYSICAL_ADDRESS	ImageLocationInMemory; 	/* PE/COFF image */
    uint64_t 			ImageLengthInMemory;
    uint64_t 			ImageLinkTimeAddress;
    uint64_t 			LengthOfDevicePath; 
    uint8_t 			*DevicePath; 		/* UEFI_DEVICE_PATH */
    char 			*Path;			/* formatted path */
} UEFI_IMAGE_LOAD_EVENT;

/* General malloced buffer and uint32_t size */

typedef struct {
    uint32_t size;
    uint8_t *buffer;
} TSS4B_BUFFER;

typedef struct {
    uint8_t                           VendorGuid[sizeof(efi_guid_t)];
    UINT64                            VendorTable;
} EFI_CONFIGURATION_TABLE;

/*
  UEFI_HANDOFF_TABLE_POINTERS

  This structure is used in EV_EFI_HANDOFF_TABLES event to facilitate
  the measurement of given configuration tables.
*/

typedef struct {
    UINT64                            NumberOfTables;
    EFI_CONFIGURATION_TABLE           *TableEntry;
} UEFI_HANDOFF_TABLE_POINTERS;

/* union of all event types */

typedef union {
    UEFI_VARIABLE_DATA 		uefiVariableData;
    UEFI_PLATFORM_FIRMWARE_BLOB uefiPlatformFirmwareBlob;
    UEFI_IMAGE_LOAD_EVENT 	uefiImageLoadEvent;
    TSS4B_BUFFER		tss4bBuffer;
    UEFI_HANDOFF_TABLE_POINTERS uefiHandoffTablePointers;
    UEFI_GPT_DATA		uefiGptData;
} TSSU_EFIData;

/* Externally visible API interface structure */

typedef struct {
    uint32_t pcrIndex;
    uint32_t eventType;		/* tag describes the union */
    TSSU_EFIData efiData;	/* union of all event types */
} TSST_EFIData;

/* Public EFI library interface */

uint32_t TSS_EFIData_Init(TSST_EFIData **efiData, uint32_t eventType);
void     TSS_EFIData_Free(TSST_EFIData *efiData);
uint32_t TSS_EFIData_ReadBuffer(TSST_EFIData *efiData,
				uint8_t *event, uint32_t eventSize,
				uint32_t pcrIndex);
void     TSS_EFIData_Trace(TSST_EFIData *efiData);
uint32_t TSS_EFIData_ToJson(TSST_EFIData *efiData);

#endif
