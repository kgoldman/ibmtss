/********************************************************************************/
/*										*/
/*			    TSS Configuration Properties			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssproperties.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
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
#include <ibmtss/TPM_Types.h>

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
#ifndef TPM_NOSOCKET
typedef int TSS_SOCKET_FD;
#endif 	/* TPM_NOSOCKET */
#endif	/* TPM_POSIX */

/* There doesn't seem to be a portable Unix MAXPATHLEN variable, so pick a large number.  The
   directory length will be (currently) 17 bytes smaller. */
#define TPM_DATA_DIR_PATH_LENGTH 256

#ifdef __cplusplus
extern "C" {
#endif

#include <ibmtss/tss.h>
#include "tssauth.h"

    /* Structure to hold session data within the context */

    typedef struct TSS_SESSIONS {
	TPMI_SH_AUTH_SESSION sessionHandle;
	uint8_t *sessionData;
	uint16_t sessionDataLength;
    } TSS_SESSIONS;

    /* Structure to hold transient or persistent object data within the context */
    
    typedef struct TSS_OBJECT_PUBLIC {
	TPM_HANDLE objectHandle;
	TPM2B_NAME name;
	TPM2B_PUBLIC objectPublic;
    } TSS_OBJECT_PUBLIC;

    /* Structure to hold NV index  data within the context */

    typedef struct TSS_NVPUBLIC {
	TPMI_RH_NV_INDEX nvIndex;
	TPM2B_NAME name;
	TPMS_NV_PUBLIC	nvPublic;
    } TSS_NVPUBLIC;

    /* Context for TSS global parameters.

       NOTE:  Keep this in sync with TSS_Properties_Init() and TSS_Delete() */

    struct TSS_CONTEXT {

	TSS_AUTH_CONTEXT *tssAuthContext;

	/* directory for persistant storage */
	const char *tssDataDirectory;

	/* encrypt saved session state */
	int tssEncryptSessions;

	/* saved session encryption key.  This seems to port to openssl 1.0 and 1.1, but will have to
	   become a malloced void * for other crypto libraries. */
#ifndef TPM_TSS_NOCRYPTO
	void *tssSessionEncKey;
	void *tssSessionDecKey;
#endif
	/* a minimal TSS with no file support stores the sessions, objects, and NV metadata in a
	   structure.  Scripting will not work, and persistent objects will not work, but a single
	   application will otherwise work. */
#ifdef TPM_TSS_NOFILE
	TSS_SESSIONS sessions[MAX_ACTIVE_SESSIONS];
	TSS_OBJECT_PUBLIC objectPublic[64];
	TSS_NVPUBLIC nvPublic[64];
#endif
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
	int tpm12Command;		/* TRUE for TPM 1.2 command */

	/* socket file descriptor */
#ifndef TPM_NOSOCKET
	TSS_SOCKET_FD sock_fd;
#endif 	/* TPM_NOSOCKET */

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
