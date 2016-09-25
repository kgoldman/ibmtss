/********************************************************************************/
/*										*/
/*			    TSS Configuration Properties			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssproperties.h 730 2016-08-23 21:09:53Z kgoldman $		*/
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

/* This is an internal TSS file, subject to change.  Applications should not include it. */

#ifndef TSSPROPERTIES_H
#define TSSPROPERTIES_H

#ifndef TPM_TSS
#define TPM_TSS
#endif
#include <tss2/TPM_Types.h>

#ifdef TPM_WINDOWS
#include <windows.h>
#include <specstrings.h>

#ifdef TPM_WINDOWS_TBSI
/* Windows 7 */
#if defined TPM_WINDOWS_TBSI_WIN7
#include <c:/progra~1/Micros~2/Windows/v7.1/include/tbs.h>
/* Windows 8, 10 */
#elif defined  TPM_WINDOWS_TBSI_WIN8
#include <tbs.h>
#else
#error "Must define either TPM_WINDOWS_TBSI_WIN7 or TPM_WINDOWS_TBSI_WIN8"
#endif
#endif

typedef SOCKET TSS_SOCKET_FD; 
#endif /* TPM_WINDOWS */

#ifdef TPM_POSIX
typedef int TSS_SOCKET_FD;
#endif	/* TPM_POSIX */

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss.h>
#include "tssauth.h"
 
/* Context for TSS global parameters */

struct TSS_CONTEXT {

    TSS_AUTH_CONTEXT *tssAuthContext;

    /* directory for persistant storage */
    const char *tssDataDirectory;

    /* encrypt saved session state */
    int tssEncryptSessions;

    /* ports, host name, server (packet) type for socket interface */
    short tssCommandPort;
    short tssPlatformPort;
    const char *tssServerName;
    const char *tssServerType;

    /* interface type */
    const char *tssInterfaceType;

    /* device driver interface */
    const char *tssDevice;

    /* TRUE for the first time through, indicates that interface open must occur */
    int tssFirstTransmit;

    /* socket file descriptor */
    TSS_SOCKET_FD sock_fd;

    /* Linux device file descriptor */
    int dev_fd;

    /* Windows device driver handle */
#ifdef TPM_WINDOWS
#ifdef TPM_WINDOWS_TBSI
    TBS_HCONTEXT hContext;
#endif
#endif

};

TPM_RC TSS_GlobalProperties_Init(void);
TPM_RC TSS_Properties_Init(TSS_CONTEXT *tssContext);
    
#ifdef __cplusplus
}
#endif



#endif
