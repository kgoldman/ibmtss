#################################################################################
#										#
#		Linux TPM 1.2 Utilities Makefile				#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile 1296 2018-08-10 13:56:48Z kgoldman $		#
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

# compile - for TSS 1.2 library

# include the hardening flag PIC needed for compiling for dynamic
# linking

CCLFLAGS += 	-I. 		\
		-I../utils	\
		-fPIC		\
		-DTPM_TPM20

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

# hardening flags for linking shared objects
LNLFLAGS += -shared -Wl,-z,now

# link - for applications, TSS path, TSS and OpenSSl libraries

# hardening flags for linking executables
LNAFLAGS += -pie -Wl,-z,now -Wl,-rpath,.

LNALIBS +=  -libmtssutils12 -libmtss -lcrypto

# TSS shared library

LIBTSS=../utils/libibmtss.so

# TSS 1.2 utilities shared library

LIBTSSUTILS12VERSIONED=libibmtssutils12.so.0.1
LIBTSSUTILS12SONAME=libibmtssutils12.so.0
LIBTSSUTILS12=libibmtssutils12.so

# executable extension

EXE =

# 

ALL = $(LIBTSSUTILS12)
TSS_HEADERS=

# default TSS 1.2 utilities library

TSSUTILS12_OBJS = ekutils12.o
TSSUTILS12_HEADERS = ekutils12.h

# common to all builds

include makefile-common

# default build target

all:	$(ALL)

# TSS 1.2 utilities shared library source

ekutils12.o: 	$(TSSUTILS12_HEADERS) ekutils12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ekutils12.c

# TSS 1.2 utilities shared library

$(LIBTSSUTILS12):	$(TSSUTILS12_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -Wl,-soname,$(LIBTSSUTILS12SONAME) \
			-o $(LIBTSSUTILS12VERSIONED) $(TSSUTILS12_OBJS) $(LNLLIBS)
		rm -f $(LIBTSSSUTIL12SONAME)
		ln -sf $(LIBTSSUTILS12VERSIONED) $(LIBTSSUTILS12SONAME)
		rm -f $(LIBTSSUTILS12)
		ln -sf $(LIBTSSUTILS12SONAME) $(LIBTSSUTILS12)

.PHONY:		clean
.PRECIOUS:	%.o

clean:		
		rm -f *.o  *~ 			\
		h*.bin				\
		$(LIBTSSUTILS12SONAME) 		\
		$(LIBTSSUTILS12VERSIONED)	\
		$(ALL)

# implemented utilities

activateidentity:	../utils/ibmtss/tss.h activateidentity.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) activateidentity.o $(LNALIBS) -o activateidentity
createendorsementkeypair: ../utils/ibmtss/tss.h createendorsementkeypair.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createendorsementkeypair.o $(LNALIBS) -o createendorsementkeypair
createwrapkey:		../utils/ibmtss/tss.h createwrapkey.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createwrapkey.o $(LNALIBS) -o createwrapkey
extend:			../utils/ibmtss/tss.h extend.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) extend.o $(LNALIBS) -o extend
flushspecific:		../utils/ibmtss/tss.h flushspecific.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) flushspecific.o $(LNALIBS) -o flushspecific
getcapability:		../utils/ibmtss/tss.h getcapability.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcapability.o $(LNALIBS) -o getcapability
loadkey2:		../utils/ibmtss/tss.h loadkey2.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) loadkey2.o $(LNALIBS) -o loadkey2
makeidentity:		../utils/ibmtss/tss.h makeidentity.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makeidentity.o $(LNALIBS) -o makeidentity
nvdefinespace:		../utils/ibmtss/tss.h nvdefinespace.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvdefinespace.o $(LNALIBS) -o nvdefinespace
nvreadvalueauth:	../utils/ibmtss/tss.h nvreadvalueauth.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadvalueauth.o $(LNALIBS) -o nvreadvalueauth
nvreadvalue:		../utils/ibmtss/tss.h nvreadvalue.o $(LIBTSS) $(LIBTSSUTILS12)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadvalue.o $(LNALIBS) -o nvreadvalue
nvwritevalueauth:	../utils/ibmtss/tss.h nvwritevalueauth.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritevalueauth.o $(LNALIBS) -o nvwritevalueauth
nvwritevalue:		../utils/ibmtss/tss.h nvwritevalue.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritevalue.o $(LNALIBS) -o nvwritevalue
oiap:			../utils/ibmtss/tss.h oiap.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) oiap.o $(LNALIBS) -o oiap
osap:			../utils/ibmtss/tss.h osap.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) osap.o $(LNALIBS) -o osap
ownerreadinternalpub:	../utils/ibmtss/tss.h ownerreadinternalpub.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ownerreadinternalpub.o $(LNALIBS) -o ownerreadinternalpub
ownersetdisable:	../utils/ibmtss/tss.h ownersetdisable.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ownersetdisable.o $(LNALIBS) -o ownersetdisable
pcrread:		../utils/ibmtss/tss.h pcrread.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrread.o $(LNALIBS) -o pcrread
quote2:			../utils/ibmtss/tss.h quote2.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) quote2.o ../utils/cryptoutils.o $(LNALIBS) -o quote2
sign:			../utils/ibmtss/tss.h sign.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sign.o ../utils/cryptoutils.o $(LNALIBS) -o sign
startup:		../utils/ibmtss/tss.h startup.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startup.o $(LNALIBS) -o startup
takeownership:		../utils/ibmtss/tss.h takeownership.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) takeownership.o $(LNALIBS) -o takeownership
tpminit:		../utils/ibmtss/tss.h tpminit.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpminit.o $(LNALIBS) -o tpminit

createekcert:		../utils/ibmtss/tss.h createekcert.o ekutils12.o \
				../utils/ekutils.o ../utils/cryptoutils.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createekcert.o ekutils12.o \
				../utils/ekutils.o ../utils/cryptoutils.o $(LNALIBS) -o createekcert
makeekblob:		../utils/ibmtss/tss.h makeekblob.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makeekblob.o $(LNALIBS) -o makeekblob
eventextend:		../utils/ibmtss/tss.h eventextend.o ../utils/eventlib.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventextend.o ../utils/eventlib.o \
				$(LNALIBS) -o eventextend
imaextend:		../utils/ibmtss/tss.h imaextend.o ../utils/imalib.o $(LIBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) imaextend.o ../utils/imalib.o \
				$(LNALIBS) -o imaextend

# for applications, not for TSS library

%.o:		%.c 
		$(CC) $(CCFLAGS) $(CCAFLAGS) $< -o $@

