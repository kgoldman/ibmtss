#################################################################################
#										#
#		Linux TPM 1.2 Utilities Makefile				#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile 1226 2018-05-22 21:14:25Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2018						#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

# C compiler

CC = /usr/bin/gcc

# compile - common flags for TSS library and applications

CCFLAGS += 	-DTPM_POSIX

# example of pointing to a locally built openssl 1.1
# CCFLAGS += 	-I/home/kgold/openssl/include

# compile - for applications

# include the hardening flag PIE needed for compiling for
# static linking

CCAFLAGS += 	-I.		\
		-I../utils	\
		-fPIE		\
		-DTPM_TPM12	

# link - common flags flags TSS library and applications

LNFLAGS += 	-DTPM_POSIX		\
		-L.			\
		-L../utils

# This seems to be required on some Ubuntu distros due to an issue with the gold linker
#		-fuse-ld=bfd

# example of pointing to a locally built openssl 1.1
# LNFLAGS +=	 -L/home/kgold/openssl
# This also requires setting the environment variable LD_LIBRARY_PATH.  E.g.,
# setenv LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:/home/kgold/openssl

# link - for TSS library

# link - for applications, TSS path, TSS and OpenSSl libraries

# hardening flags for linking executables
LNAFLAGS += -pie -Wl,-z,now -Wl,-rpath,.

LNALIBS +=  -libmtss -lcrypto

# shared library

# versioned shared library
LIBTSSVERSIONED=../utils/libibmtss.so.0.1

# soname field of the shared library
# which will be made symbolic link to the versioned shared library
# this is used to provide version backward-compatibility information
LIBTSSSONAME=../utils/libibmtss.so.0

# symbolic link to the versioned shared library
# this allows linking to the shared library with '-ltss' 

LIBTSS=../utils/libibmtss.so


# executable extension

EXE =

# 

ALL =
TSS_HEADERS=

# default TSS library

# common to all builds

include makefile-common

# default build target

all:	$(ALL)


.PHONY:		clean
.PRECIOUS:	%.o

clean:		
		rm -f *.o  *~ 	\
		h*.bin		\
		$(ALL)

# implemented utilities

activateidentity:	../utils/tss2/tss.h activateidentity.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) activateidentity.o $(LNALIBS) -o activateidentity
createendorsementkeypair: ../utils/tss2/tss.h createendorsementkeypair.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createendorsementkeypair.o $(LNALIBS) -o createendorsementkeypair
createwrapkey:		../utils/tss2/tss.h createwrapkey.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createwrapkey.o $(LNALIBS) -o createwrapkey
extend:			../utils/tss2/tss.h extend.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) extend.o $(LNALIBS) -o extend
flushspecific:		../utils/tss2/tss.h flushspecific.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) flushspecific.o $(LNALIBS) -o flushspecific
getcapability:		../utils/tss2/tss.h getcapability.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcapability.o $(LNALIBS) -o getcapability
loadkey2:		../utils/tss2/tss.h loadkey2.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) loadkey2.o $(LNALIBS) -o loadkey2
makeidentity:		../utils/tss2/tss.h makeidentity.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makeidentity.o $(LNALIBS) -o makeidentity
nvdefinespace:		../utils/tss2/tss.h nvdefinespace.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvdefinespace.o $(LNALIBS) -o nvdefinespace
nvreadvalueauth:	../utils/tss2/tss.h nvreadvalueauth.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadvalueauth.o $(LNALIBS) -o nvreadvalueauth
nvreadvalue:		../utils/tss2/tss.h nvreadvalue.o  ekutils12.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadvalue.o  ekutils12.o $(LNALIBS) -o nvreadvalue
nvwritevalueauth:	../utils/tss2/tss.h nvwritevalueauth.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritevalueauth.o $(LNALIBS) -o nvwritevalueauth
nvwritevalue:		../utils/tss2/tss.h nvwritevalue.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritevalue.o $(LNALIBS) -o nvwritevalue
oiap:			../utils/tss2/tss.h oiap.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) oiap.o $(LNALIBS) -o oiap
osap:			../utils/tss2/tss.h osap.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) osap.o $(LNALIBS) -o osap
ownerreadinternalpub:	../utils/tss2/tss.h ownerreadinternalpub.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ownerreadinternalpub.o $(LNALIBS) -o ownerreadinternalpub
ownersetdisable:	../utils/tss2/tss.h ownersetdisable.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ownersetdisable.o $(LNALIBS) -o ownersetdisable
pcrread:		../utils/tss2/tss.h pcrread.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrread.o $(LNALIBS) -o pcrread
quote2:			../utils/tss2/tss.h quote2.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) quote2.o ../utils/cryptoutils.o $(LNALIBS) -o quote2
sign:			../utils/tss2/tss.h sign.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sign.o ../utils/cryptoutils.o $(LNALIBS) -o sign
startup:		../utils/tss2/tss.h startup.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startup.o $(LNALIBS) -o startup
takeownership:		../utils/tss2/tss.h takeownership.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) takeownership.o $(LNALIBS) -o takeownership
tpminit:		../utils/tss2/tss.h tpminit.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpminit.o $(LNALIBS) -o tpminit

createekcert:		../utils/tss2/tss.h createekcert.o ekutils12.o \
				../utils/ekutils.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createekcert.o ekutils12.o \
				../utils/ekutils.o ../utils/cryptoutils.o $(LNALIBS) -o createekcert
makeekblob:		../utils/tss2/tss.h makeekblob.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makeekblob.o $(LNALIBS) -o makeekblob
eventextend:		../utils/tss2/tss.h eventextend.o ../utils/eventlib.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventextend.o ../utils/eventlib.o \
				$(LNALIBS) -o eventextend
imaextend:		../utils/tss2/tss.h imaextend.o ../utils/imalib.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) imaextend.o ../utils/imalib.o \
				$(LNALIBS) -o imaextend

# for applications, not for TSS library

%.o:		%.c 
		$(CC) $(CCFLAGS) $(CCAFLAGS) $< -o $@

