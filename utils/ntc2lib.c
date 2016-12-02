/********************************************************************************/
/*										*/
/*	     	TPM2 Novoton Proprietary Command Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2lib.c 827 2016-11-18 20:45:01Z kgoldman $		*/
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

#include "ntc2lib.h"

/* Marshal and Unmarshal Functions */

TPM_RC
NTC2_CFG_STRUCT_Unmarshal(NTC2_CFG_STRUCT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    /* assumes that the NTC2_CFG_STRUCT structure are all uint8_t so that there are no endian
       issues */
    if (rc == TPM_RC_SUCCESS) {
	rc = Array_Unmarshal((BYTE *)target, sizeof(NTC2_CFG_STRUCT), buffer, size);
    }
    return rc;
}
    
TPM_RC
NTC2_PreConfig_In_Unmarshal(NTC2_PreConfig_In *target, BYTE **buffer, INT32 *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = NTC2_CFG_STRUCT_Unmarshal(&target->preConfig, buffer, size);	
	if (rc != TPM_RC_SUCCESS) {	
	    rc += RC_NTC2_PreConfig_preConfig;
	}
    }
    return rc;
}

