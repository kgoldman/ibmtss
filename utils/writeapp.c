/********************************************************************************/
/*										*/
/*			    NV Write Application				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: writeapp.c 682 2016-07-15 18:49:19Z kgoldman $		*/
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

/* Preprovisioning:
   
   nvdefinespace -hi o -ha 01000000 -pwdn pwd -sz 1
   nvreadpublic -ha 01000000
   createprimary -hi o
   create -den -hp 80000000 -opu tmppub.bin -opr tmppriv.bin
   load -hp 80000000 -ipu tmppub.bin -ipr tmppriv.bin 
*/

/* 
   Demo application

   Write a provisioned NV location at 01000000, byte [0] with data 0xff;

   with password pwd, using a bound, salted HMAC SHA-256 session.

   Use AES CFB encryption for the write parameter.

   Assumes a salt key loaded at 80000001
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;
    NV_Write_In			nvWriteIn;
 
    argc = argc;
    argv = argv;

    /*	Start an authorization session */
    if (rc == 0) {
	startAuthSessionIn.tpmKey = 0x80000001;		/* salt key */
	startAuthSessionIn.bind = 0x01000000;		/* bind object */
	startAuthSessionExtra.bindPassword = "pwd";
	startAuthSessionIn.sessionType = TPM_SE_HMAC;	/* HMAC session */
	startAuthSessionIn.authHash = TPM_ALG_SHA256;	/* HMAC SHA-256 */
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;	/* parameter encryption */
	startAuthSessionIn.symmetric.keyBits.aes = 128;
	startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    /* NV write */
    if (rc == 0) {
	nvWriteIn.authHandle = 0x01000000;	/* use index authorization */
	nvWriteIn.nvIndex = 0x01000000;		/* NV index to write */
	nvWriteIn.data.t.size = 1;		/* one byte */
	nvWriteIn.data.t.buffer[0] = 0xff;	/* data */
	nvWriteIn.offset = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&nvWriteIn,	
			 NULL,
			 TPM_CC_NV_Write,
			 startAuthSessionOut.sessionHandle, NULL, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printf("writeapp: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("writeapp: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}
    
