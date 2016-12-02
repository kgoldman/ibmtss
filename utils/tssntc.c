/********************************************************************************/
/*										*/
/*		     	TPM2 Novoton Proprietary Commands			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssntc.c 682 2016-07-15 18:49:19Z kgoldman $			*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/Unmarshal_fp.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssprint.h>
#include "tssntc.h"

/* Marshal and Unmarshal Functions */

TPM_RC
TSS_NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshal((BYTE *)source, sizeof(NTC2_CFG_STRUCT), written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NTC2_PreConfig_In_Marshal(NTC2_PreConfig_In *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_NTC2_CFG_STRUCT_Marshal(&source->preConfig, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NTC2_GetConfig_Out_Unmarshal(NTC2_GetConfig_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    tag = tag;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = NTC2_CFG_STRUCT_Unmarshal(&target->preConfig, buffer, size);
    }
    return rc;
}

