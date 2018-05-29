/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: Parameters12.h 1189 2018-05-01 13:27:40Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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

#ifndef PARAMETERS12_H
#define PARAMETERS12_H

#include <tss2/ActivateIdentity_fp.h>
#include <tss2/CreateWrapKey_fp.h>
#include <tss2/CreateEndorsementKeyPair_fp.h>
#include <tss2/Extend_fp.h>
#include <tss2/FlushSpecific_fp.h>
#include <tss2/GetCapability12_fp.h>
#include <tss2/MakeIdentity_fp.h>
#include <tss2/NV_DefineSpace12_fp.h>
#include <tss2/NV_ReadValue_fp.h>
#include <tss2/NV_ReadValueAuth_fp.h>
#include <tss2/NV_WriteValue_fp.h>
#include <tss2/NV_WriteValueAuth_fp.h>
#include <tss2/OIAP_fp.h>
#include <tss2/OSAP_fp.h>
#include <tss2/OwnerReadInternalPub_fp.h>
#include <tss2/OwnerSetDisable_fp.h>
#include <tss2/LoadKey2_fp.h>
#include <tss2/PcrRead12_fp.h>
#include <tss2/PCR_Reset12_fp.h>
#include <tss2/Quote2_fp.h>
#include <tss2/ReadPubek_fp.h>
#include <tss2/Sign12_fp.h>
#include <tss2/Startup12_fp.h>
#include <tss2/TakeOwnership_fp.h>

#endif
