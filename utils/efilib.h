/********************************************************************************/
/*										*/
/*		     	EFI Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2021.						*/
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

#define TSS_EFI_GUID_SIZE 16

/* TSS_EFI_SIGNATURE_DATA from UEFI specification */

typedef struct {
    uint8_t   SignatureOwner[TSS_EFI_GUID_SIZE];
    uint8_t  *SignatureData;
} TSS_EFI_SIGNATURE_DATA;

typedef struct {
    uint8_t   SignatureOwner[TSS_EFI_GUID_SIZE];
    uint8_t  *SignatureData;
    /* since EV_EFI_VARIABLE_AUTHORITY doesn't have an explicit length */
    uint32_t  SignatureLength;
} TSS_AUTHORITY_SIGNATURE_DATA;

/* TSS_UEFI_VARIABLE_DATA VariableData contents for EV_EFI_VARIABLE_DRIVER_CONFIG and guid for PK
   KEK db dbx dbt dbr */

typedef struct {
    uint8_t  SignatureType[TSS_EFI_GUID_SIZE];
    uint32_t SignatureListSize;		/* includes the header */
    uint32_t SignatureHeaderSize;
    uint32_t SignatureSize;		/* size of each signature */
    /* Header before the array of signatures. The format of this header is specified by the
       SignatureType. */
    uint8_t  *SignatureHeader;		/* [SignatureHeaderSize] */
    TSS_EFI_SIGNATURE_DATA *Signatures;	/* Array of EFI_SIGNATURE_DATA */
    /* NOTE This is not part of EFI structure */
    uint32_t signaturesCount;
} TSS_EFI_SIGNATURE_LIST;

/* TSS_UEFI_VARIABLE_DATA VariableData contents for EV_EFI_VARIABLE_DRIVER_CONFIG */
typedef struct {
    int enabled;	/* boolean */
    /* EV_EFI_VARIABLE_DRIVER_CONFIG PK KEK db dbx dbt dbr */
    uint32_t signatureListCount;
    TSS_EFI_SIGNATURE_LIST *signatureList;
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
    uint8_t  DiskGUID[TSS_EFI_GUID_SIZE];
    uint64_t PartitionEntryLBA;
    uint32_t NumberOfPartitionEntries;
    uint32_t SizeOfPartitionEntry;
    uint32_t PartitionEntryArrayCRC32;
    uint8_t  *Reserved2;
} TSS_UEFI_PARTITION_TABLE_HEADER;

/* GPT Parition Table Attributes UEFI Table 24 */

#define TSS_UEFI_REQUIRED_PARTITION 0x0000000000000001
#define TSS_UEFI_NO_BLOCK_IO	0x0000000000000002
#define TSS_UEFI_LEGACY_BIOS	0x0000000000000003

/* UEFI Specification Version 2.8 Section 5.3 Table 22 */

typedef struct {
    uint8_t PartitionTypeGUID[TSS_EFI_GUID_SIZE];
    uint8_t UniquePartitionGUID[TSS_EFI_GUID_SIZE];
    uint64_t StartingLBA;
    uint64_t EndingLBA;
    uint64_t Attributes;	/* UEFI Table 24 */
    uint8_t PartitionName[72]; 	/* Null-terminated string containing name of the partition */
} TSS_UEFI_PARTITION_ENTRY;

/* EV_EFI_GPT_EVENT */

typedef struct  {
    TSS_UEFI_PARTITION_TABLE_HEADER UEFIPartitionHeader;
    uint64_t NumberOfPartitions;
    TSS_UEFI_PARTITION_ENTRY *Partitions;
} TSS_UEFI_GPT_DATA;

/* EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER */

/* from UEFI specification */
typedef struct {
    uint8_t Type;
    uint8_t SubType;
    uint16_t Length;
} TSS_EFI_DEVICE_PATH_PROTOCOL;

/* type 1 subtype 1 HW PCI  device */

typedef struct {
    uint8_t Function;
    uint8_t Device;
} TSS_HW0101;

/* type 1 subtype 4 HW Vendor  device */

typedef struct {
    uint8_t Vendor_GUID[TSS_EFI_GUID_SIZE];
} TSS_HW0104;

/* type 2 subtype 1 ACPI device */

typedef struct {
    uint32_t HID;
    uint32_t UID;
} TSS_ACPI0201;

/* type 3 subtype 02 Msg SCSI 10.3.4.2 SCSI Device Path */

typedef struct {
    uint16_t 	TargetID;
    uint16_t 	LogicalUnitNumber;
} TSS_MSG0302;

/* type 3 subtype 05 Msg USB 10.3.4.5 USB Device Paths */

typedef struct {
    uint8_t USBParentPort;
    uint8_t Interface;
} TSS_MSG0305;

/* type 3 subtype 0A Msg Vendor Defined 10.3.4.17 Vendor-Defined Messaging Device Path */

typedef struct {
    uint8_t   VendorGUID[TSS_EFI_GUID_SIZE];
    /* uint8_t  *VendorData; uses unionBuffer */
} TSS_MSG030A;

/* type 3 subtype 0b Msg MAC 10.3.4.11 MAC Address Device Path */

typedef struct {
    uint8_t Mac[32];
    uint8_t IfType;	/*  https://tools.ietf.org/html/rfc1700
			    https://tools.ietf.org/html/rfc1213*/
} TSS_MSG030B;

/* type 3 subtype 0c Msg IPv4 10.3.4.12 IPv4 Device Path */

typedef struct {
    uint8_t LocalIPAddress[4];
    uint8_t RemoteIPAddress[4];
    uint16_t LocalPort;	/* https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers */
    uint16_t RemotePort;
    uint16_t Protocol;	/* https://tools.ietf.org/html/rfc1700
			   Assigned Internet Protocol Numbers*/
    uint8_t StaticIPAddress;
    uint8_t GatewayIPAddress[4];
    uint8_t SubnetMask[4];
} TSS_MSG030C;

/* type 3 subtype 0d Msg IPv6 10.3.4.13 IPv6 Device Path */

typedef struct {
    uint8_t LocalIPAddress[16];
    uint8_t RemoteIPAddress[16];
    uint16_t LocalPort;	/* https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers */
    uint16_t RemotePort;
    uint16_t Protocol;	/* https://tools.ietf.org/html/rfc1700
			   Assigned Internet Protocol Numbers*/
    uint8_t IPAddressOrigin;
    uint8_t PrefixLength;
    uint8_t GatewayIPAddress[16];
} TSS_MSG030D;

/* type 3 subtype 0f Msg USB Class 10.3.4.9 USB Device Path (Class)*/

typedef struct {
    uint16_t VendorID;
    uint16_t ProductID;
    uint8_t DeviceClass;
    uint8_t DeviceSubclass;
    uint8_t DeviceProtocol;
} TSS_MSG030F;

/* type 3 subtype 12 Msg SATA 10.3.4.6 SATA Device Path */

typedef struct {
    uint16_t 	HBAPortNumber;
    uint16_t 	PortMultiplierPort;
    uint16_t 	LogicalUnitNumber;
} TSS_MSG0312;

/* type 3 subtype 17 Msg NVME */

typedef struct {
    uint32_t 	NamespaceId;
    uint64_t 	NamespaceUuid;
} TSS_MSG0317;

/* type 3 subtype 18 Msg URI 10.3.4.23 Uniform Resource Identifiers (URI) Device Path */
/* The *URI uses the general purpose malloced buffer */

/* type 4 subtype 1 Media HD */

typedef struct {
    uint32_t PartitionNumber;
    uint64_t PartitionStart;
    uint64_t PartitionSize;
    uint8_t PartitionSignature[16];
    uint8_t PartitionFormat;
    uint8_t SignatureType;
} TSS_MEDIA0401;

/* type 4 subtype 8 Media Offset */

typedef struct {
    uint32_t Reserved;
    uint64_t StartingOffset;
    uint64_t EndingOffset;
} TSS_MEDIA0408;

typedef struct {
    TSS_EFI_DEVICE_PATH_PROTOCOL protocol;
    uint8_t 	*data;
    /* type 4 subtype 4 Media File Path */
    uint32_t	bufferLength;
    uint8_t 	*buffer;
    /* general purpose malloced buffer, outside union to make free easier */
    /* used for Message URI, Message Vendor */
    uint32_t	unionBufferLength;
    uint8_t 	*unionBuffer;
    /* union based on Type and SubType */
    union {
	/* type 1 subtype 1 HW PCI device */
	TSS_HW0101 hw0101;
	/* type 1 subtype 4 HW Vendor device */
	TSS_HW0104 hw0104;
	/* type 2 subtype 1 ACPI ACPI device */
	TSS_ACPI0201 acpi0201;
	/* type 3 subtype 02 Msg MAC */
	TSS_MSG0302 msg0302;
	/* type 3 subtype 05 Msg USB */
	TSS_MSG0305 msg0305;
	/* type 3 subtype 0A Msg Vendor Defined */
	TSS_MSG030A msg030a;
	/* type 3 subtype 0b Msg MAC */
	TSS_MSG030B msg030b;
	/* type 3 subtype 0c Msg IPv4 */
	TSS_MSG030C msg030c;
	/* type 3 subtype 0D Msg ipV6 */
	TSS_MSG030D msg030d;
	/* type 3 subtype 0f Msg USB */
	TSS_MSG030F msg030f;
	/* type 3 subtype 12 Msg SATA */
	TSS_MSG0312 msg0312;
	/* type 3 subtype 17 Msg NVME */
	TSS_MSG0317 msg0317;
	/* type 4 subtype 1 Media HD */
	TSS_MEDIA0401 media0401;
	/* type 4 subtype 8 Media Offset */
	TSS_MEDIA0408 media0408;
    };
} TSS_UEFI_DEVICE_PATH;

/* EV_COMPACT_HASH is currently just an unstructured buffer and size */

/* TSS_UEFI_VARIABLE_DATA structure tags, for this implementation */

#define TSS_VAR_UNKNOWN		0
#define TSS_VAR_SECUREBOOT	1
#define TSS_VAR_PK		2
#define TSS_VAR_KEK		3
#define TSS_VAR_DB		4
#define TSS_VAR_DBX		5
#define TSS_VAR_DBT		6
#define TSS_VAR_DBR		7
#define TSS_VAR_BOOTORDER	8
#define TSS_VAR_BOOTPATH	9
#define TSS_VAR_SHIM		10
#define TSS_VAR_MOKLIST		11
#define TSS_VAR_AUDITMODE	12
#define TSS_VAR_DEPLOYEDMODE 	13
#define TSS_VAR_SETUPMODE	14
#define TSS_VAR_MOKLISTX	15

/* EV_EFI_VARIABLE_BOOT BootOrder */

typedef struct  {
    uint32_t bootOrderListCount;
    uint16_t *bootOrderList;	/* array of Bootxxxx entries */
} TSS_VARIABLE_BOOT_ORDER;

/* EV_EFI_VARIABLE_BOOT not BootOrder */

typedef struct  {
    uint32_t Attributes;
    uint16_t FilePathListLength;
    uint32_t DescriptionLength;
    uint8_t *Description;
    uint32_t UefiDevicePathCount;
    TSS_UEFI_DEVICE_PATH *UefiDevicePath;	/* array of TSS_UEFI_DEVICE_PATH structures */
} TSS_VARIABLE_BOOT;

/* This structure is used to designate the measurement of UEFI variables. The
   structure is defined in the TGC PC Client Platform Firmware Profile Specification
   Revision 1.04 Section 9.2.6. */

typedef struct {
    uint8_t VariableName[TSS_EFI_GUID_SIZE];
    uint64_t UnicodeNameLength;
    uint64_t VariableDataLength;
    uint8_t *UnicodeName;
    uint8_t *VariableData;
    /* NOTE: The following are not part of TSS_UEFI_VARIABLE_DATA structure */
    int variableDataTag;	/* tag for following union */
    /* subclasses */
    union {
	/* EV_EFI_VARIABLE_DRIVER_CONFIG subclass for tag PK KEK db dbx dbr dbt SecureBoot
	   secureboot */
	TSS_VARIABLE_DRIVER_CONFIG variableDriverConfig;
	/* EV_EFI_VARIABLE_BOOT subclass for tag VAR_BOOTORDER */
	TSS_VARIABLE_BOOT_ORDER variableBootOrder;
	/* EV_EFI_VARIABLE_BOOT subclass for tag not VAR_BOOTORDER */
	TSS_VARIABLE_BOOT variableBoot;
	/* EV_EFI_VARIABLE_AUTHORITY */
	TSS_AUTHORITY_SIGNATURE_DATA authoritySignatureData;
    };
} TSS_UEFI_VARIABLE_DATA;

typedef uint64_t UEFI_PHYSICAL_ADDRESS;

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

typedef struct {
    UEFI_PHYSICAL_ADDRESS   BlobBase;
    uint64_t 		    BlobLength;
} TSS_UEFI_PLATFORM_FIRMWARE_BLOB;

/* EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER */

typedef struct {
    UEFI_PHYSICAL_ADDRESS	ImageLocationInMemory; 	/* PE/COFF image */
    uint64_t 			ImageLengthInMemory;
    uint64_t 			ImageLinkTimeAddress;
    uint64_t 			LengthOfDevicePath;
    uint8_t 			*DevicePath; 		/* TSS_UEFI_DEVICE_PATH */
    /* NOTE Below are not part of the PFP structure */
    char 			*Path;			/* formatted path */
    uint32_t			UefiDevicePathCount;
    TSS_UEFI_DEVICE_PATH	*UefiDevicePath;	/* array of TSS_UEFI_DEVICE_PATH structures */
} TSS_UEFI_IMAGE_LOAD_EVENT;

/* General malloced buffer and uint32_t size */

typedef struct {
    uint32_t size;
    uint8_t *buffer;
} TSS4B_BUFFER;

typedef struct {
    uint8_t                           VendorGuid[TSS_EFI_GUID_SIZE];
    uint64_t                          VendorTable;
} TSS_EFI_CONFIGURATION_TABLE;

/*
  TSS_UEFI_HANDOFF_TABLE_POINTERS

  This structure is used in EV_EFI_HANDOFF_TABLES event to facilitate
  the measurement of given configuration tables.
*/

typedef struct {
    uint64_t                          NumberOfTables;
    TSS_EFI_CONFIGURATION_TABLE           *TableEntry;
} TSS_UEFI_HANDOFF_TABLE_POINTERS;

/* EV_EVENT_TAG */

typedef struct {
    uint32_t	taggedEventID;
    uint32_t	taggedEventDataSize;
    uint8_t	*taggedEventData;
} TSS_PCClientTaggedEvent;

typedef struct {
    uint32_t 			count;
    TSS_PCClientTaggedEvent	*taggedEvent;
} TSS_UEFI_TAGGED_EVENT;

/* EV_POST_CODE */

/* tag types */

#define TSS_EV_POST_CODE_UNKNOWN 	0
#define TSS_EV_POST_CODE_BLOB 		1
#define TSS_EV_POST_CODE_BLOB2 		2
#define TSS_EV_POST_CODE_ASCII 		3

typedef struct TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 {
    uint8_t 				BlobDescriptionSize;
    uint8_t				*BlobDescription;
    /* uint8_t  *BlobDescription uses unionBuffer */
    UEFI_PHYSICAL_ADDRESS  		BlobBase;
    uint64_t				BlobLength;
} TSS_UEFI_PLATFORM_FIRMWARE_BLOB2;

typedef union {
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB		firmwareBlob;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2	firmwareBlob2;
} TSSU_POST_CODE;

typedef struct {
    uint32_t		tag;
    /* for TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 BlobDescription or ASCII string */
    uint32_t		unionBufferLength;
    uint8_t		*unionBuffer;
    TSSU_POST_CODE	postCode;
} TSS_POST_CODE_TAGGED_EVENT;

/* union of all event types */

typedef union {
    TSS_UEFI_VARIABLE_DATA 		uefiVariableData;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB uefiPlatformFirmwareBlob;
    TSS_UEFI_IMAGE_LOAD_EVENT 	uefiImageLoadEvent;
    TSS4B_BUFFER		tss4bBuffer;
    TSS_UEFI_HANDOFF_TABLE_POINTERS uefiHandoffTablePointers;
    TSS_UEFI_GPT_DATA		uefiGptData;
    TSS_UEFI_TAGGED_EVENT 	taggedEventList;
    TSS_POST_CODE_TAGGED_EVENT	postTaggedEvent;
} TSSU_EFIData;

/* Externally visible API interface structure */

typedef struct {
    uint32_t pcrIndex;
    uint32_t eventType;		/* tag describes the union */
    TSSU_EFIData efiData;	/* union of all event types */
} TSST_EFIData;

/* Public EFI library interface */

/* specIdEvent can be NULL, but may be needed to handle PFP differences */

uint32_t TSS_EFIData_Init(TSST_EFIData **efiData, uint32_t eventType,
			  const TCG_EfiSpecIDEvent *specIdEvent);
void     TSS_EFIData_Free(TSST_EFIData *efiData,
			  const TCG_EfiSpecIDEvent *specIdEvent);
uint32_t TSS_EFIData_ReadBuffer(TSST_EFIData *efiData,
				uint8_t *event, uint32_t eventSize,
				uint32_t pcrIndex,
				const TCG_EfiSpecIDEvent *specIdEvent);
void     TSS_EFIData_Trace(TSST_EFIData *efiData,
			   const TCG_EfiSpecIDEvent *specIdEvent);
uint32_t TSS_EFIData_ToJson(TSST_EFIData *efiData,
			    const TCG_EfiSpecIDEvent *specIdEvent);

#endif
