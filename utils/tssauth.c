/********************************************************************************/
/*										*/
/*		Common TPM 1.2 and TPM 2.0 TSS Authorization 			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: tssauth.c 1157 2018-04-17 14:09:56Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2018.					*/
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

/* This layer handles command and response packet authorization parameters. */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <tss2/tsserror.h>
#include <tss2/tssprint.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsstransmit.h>
#include "tssproperties.h"
#include <tss2/tssresponsecode.h>

#include "tssauth.h"

extern int tssVerbose;
extern int tssVverbose;

/* TSS_AuthCreate() allocates and initializes a TSS_AUTH_CONTEXT */

TPM_RC TSS_AuthCreate(TSS_AUTH_CONTEXT **tssAuthContext)
{
    TPM_RC rc = 0;
    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)tssAuthContext, sizeof(TSS_AUTH_CONTEXT));
   }
    if (rc == 0) {
	TSS_InitAuthContext(*tssAuthContext);
    }
    return rc;
}

/* TSS_InitAuthContext() sets initial values for an allocated TSS_AUTH_CONTEXT */

void TSS_InitAuthContext(TSS_AUTH_CONTEXT *tssAuthContext)
{
    memset(tssAuthContext->commandBuffer, 0, MAX_COMMAND_SIZE);
    memset(tssAuthContext->responseBuffer, 0, MAX_RESPONSE_SIZE);
    tssAuthContext->commandText = NULL;
    tssAuthContext->commandCode = 0;
    tssAuthContext->responseCode = 0;
    tssAuthContext->commandHandleCount = 0;
    tssAuthContext->responseHandleCount = 0;
    tssAuthContext->authCount = 0;
    tssAuthContext->commandSize = 0;
    tssAuthContext->cpBufferSize = 0;
    tssAuthContext->cpBuffer = NULL;
    tssAuthContext->responseSize = 0;
    tssAuthContext->marshalInFunction = NULL;
    tssAuthContext->unmarshalOutFunction = NULL;
    tssAuthContext->unmarshalInFunction = NULL;
#ifdef TPM_TPM12
    tssAuthContext->sessionNumber = 0xffff;	/* no encrypt sessions */
    tssAuthContext->encAuthOffset0 = 0;
    tssAuthContext->encAuthOffset1 = 0;
#endif
    return;
}

/* TSS_AuthDelete() re-initializes and then frees an allocated TSS_AUTH_CONTEXT */

TPM_RC TSS_AuthDelete(TSS_AUTH_CONTEXT *tssAuthContext)
{
    if (tssAuthContext != NULL) {
	TSS_InitAuthContext(tssAuthContext);
	free(tssAuthContext);
    }
    return 0;
}

TPM_CC TSS_GetCommandCode(TSS_AUTH_CONTEXT *tssAuthContext)
{
    TPM_CC commandCode = tssAuthContext->commandCode;
    return commandCode;
}

TPM_RC TSS_GetCpBuffer(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *cpBufferSize,
		       uint8_t **cpBuffer)
{
    *cpBufferSize = tssAuthContext->cpBufferSize;
    *cpBuffer = tssAuthContext->cpBuffer;
    return 0;
}

/* TSS_GetCommandHandleCount() returns the number of handles in the command area */

TPM_RC TSS_GetCommandHandleCount(TSS_AUTH_CONTEXT *tssAuthContext,
				 size_t *commandHandleCount)
{
    *commandHandleCount = tssAuthContext->commandHandleCount;
    return 0;
}

TPM_RC TSS_AuthExecute(TSS_CONTEXT *tssContext)
{
    TPM_RC rc = 0;
    if (tssVverbose) printf("TSS_AuthExecute: Executing %s\n",
			    tssContext->tssAuthContext->commandText);
    /* transmit the command and receive the response.  Normally returns the TPM response code. */
    if (rc == 0) {
	rc = TSS_Transmit(tssContext,
			  tssContext->tssAuthContext->responseBuffer,
			  &tssContext->tssAuthContext->responseSize,
			  tssContext->tssAuthContext->commandBuffer,
			  tssContext->tssAuthContext->commandSize,
			  tssContext->tssAuthContext->commandText);
    }
    return rc;
}
