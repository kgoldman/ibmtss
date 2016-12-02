/********************************************************************************/
/*										*/
/*		     	Nuvoton Command Common Routines				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssntc.h 730 2016-08-23 21:09:53Z kgoldman $			*/
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

#ifndef TSSNTC2_H
#define TSSNTC2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef TPM_TSS
#define TPM_TSS
#endif
#include <tss2/TPM_Types.h>
#include "ntc2lib.h"

TPM_RC
NTC2_PreConfig_In_Unmarshal(NTC2_PreConfig_In *target, BYTE **buffer, INT32 *size, TPM_HANDLE handles[]);
TPM_RC
TSS_NTC2_PreConfig_In_Marshal(NTC2_PreConfig_In *source, UINT16 *written, BYTE **buffer, INT32 *size);

TPM_RC
TSS_NTC2_GetConfig_Out_Unmarshal(NTC2_GetConfig_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
UINT16
NTC2_GetConfig_Out_Marshal(NTC2_GetConfig_Out *source, TPMI_ST_COMMAND_TAG tag, BYTE **buffer, INT32 *size);

TPM_RC
NTC2_CFG_STRUCT_Unmarshal(NTC2_CFG_STRUCT *target, BYTE **buffer, INT32 *size);
TPM_RC
TSS_NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, UINT16 *written, BYTE **buffer, INT32 *size);
UINT16
NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, BYTE **buffer, INT32 *size);


#endif
