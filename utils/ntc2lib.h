/********************************************************************************/
/*										*/
/*	     	TPM2 Novoton Proprietary Command Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2lib.h 827 2016-11-18 20:45:01Z kgoldman $		*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2016				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
/********************************************************************************/

#ifndef NTC2LIB_H
#define NTC2LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef TPM_TSS
#include "TpmTypes.h"
#include "Unmarshal_fp.h"
#else
#include <tss2/TPM_Types.h>
#include <tss2/Unmarshal_fp.h>
#endif

/* default values for System P I2C */

#define PREQUIRED_i2cLoc1_2    	0xff
#define PREQUIRED_i2cLoc3_4    	0xff
#define PREQUIRED_AltCfg	0x03
#define PREQUIRED_Direction   	0x00
#define PREQUIRED_PullUp    	0xff
#define PREQUIRED_PushPull    	0xff
#define PREQUIRED_CFG_A    	0xfe
#define PREQUIRED_CFG_B    	0xff
#define PREQUIRED_CFG_C    	0xff
#define PREQUIRED_CFG_D    	0xff
#define PREQUIRED_CFG_E    	0xff
#define PREQUIRED_CFG_F    	0xff
#define PREQUIRED_CFG_G    	0xff
#define PREQUIRED_CFG_H    	0xff
#define PREQUIRED_CFG_I    	0xff
#define PREQUIRED_CFG_J    	0xff
#define PREQUIRED_IsValid    	0xaa
#define PREQUIRED_IsLocked	0x00;

/* required values, others not supported */

#define FIXED_Direction   	0x00
#define FIXED_PullUp    	0xff
#define FIXED_PushPull    	0xff
#define FIXED_CFG_F    		0xff
#define FIXED_CFG_I    		0xff
#define FIXED_CFG_J    		0xff
#define FIXED_IsValid    	0xaa

typedef struct tdNTC2_CFG_STRUCT {
    uint8_t i2cLoc1_2;
    uint8_t i2cLoc3_4;
    uint8_t AltCfg;
    uint8_t Direction;
    uint8_t PullUp;
    uint8_t PushPull;
    uint8_t CFG_A;
    uint8_t CFG_B;
    uint8_t CFG_C;
    uint8_t CFG_D;
    uint8_t CFG_E;
    uint8_t CFG_F;
    uint8_t CFG_G;
    uint8_t CFG_H;
    uint8_t CFG_I;
    uint8_t CFG_J;
    uint8_t IsValid;	/* Must be AAh */
    uint8_t IsLocked;	/* Ignored on NTC2_PreConfig, NTC2_GetConfig returns AAh once configuration
			   is locked. */
} NTC2_CFG_STRUCT;

typedef struct {
    NTC2_CFG_STRUCT preConfig;
} NTC2_PreConfig_In;     

typedef struct {
    NTC2_CFG_STRUCT preConfig;
} NTC2_GetConfig_Out;     


#define RC_NTC2_PreConfig_preConfig (TPM_RC_P + TPM_RC_1)

TPM_RC
NTC2_PreConfig_In_Unmarshal(NTC2_PreConfig_In *target, BYTE **buffer, INT32 *size, TPM_HANDLE handles[]);
TPM_RC
TSS_NTC2_PreConfig_In_Marshal(NTC2_PreConfig_In *source, UINT16 *written, BYTE **buffer, INT32 *size);

TPM_RC
NTC2_GetConfig_Out_Unmarshal(NTC2_GetConfig_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
UINT16
NTC2_GetConfig_Out_Marshal(NTC2_GetConfig_Out *source, TPMI_ST_COMMAND_TAG tag, BYTE **buffer, INT32 *size);

TPM_RC
NTC2_CFG_STRUCT_Unmarshal(NTC2_CFG_STRUCT *target, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, UINT16 *written, BYTE **buffer, INT32 *size);
UINT16
NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, BYTE **buffer, INT32 *size);


#endif
