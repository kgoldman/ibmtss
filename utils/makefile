#################################################################################
#										#
#		Linux TPM2 Utilities Makefile					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile 1221 2018-05-16 21:10:46Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2014, 2018					#
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

# compile - for TSS library

# include the hardening flag PIC needed for compiling for dynamic
# linking

CCLFLAGS += 	-I. 		\
		-fPIC		\
		-DTPM_TPM20

# to compile out printf's.  Regression test will fail because it tries
# to print a structure -DTPM_TSS_NO_PRINT

# example of changing the default interface type
#	-DTPM_INTERFACE_TYPE_DEFAULT="\"dev\""

# compile - for applications

# include the hardening flag PIE needed for compiling for
# static linking

CCAFLAGS += 	-I.		\
		-DTPM_TPM20	\
		-fPIE

# link - common flags flags TSS library and applications

LNFLAGS += 	-DTPM_POSIX		\
		-L.

# This seems to be required on some Ubuntu distros due to an issue with the gold linker
#		-fuse-ld=bfd

# example of pointing to a locally built openssl 1.1
# LNFLAGS +=	 -L/home/kgold/openssl
# This also requires setting the environment variable LD_LIBRARY_PATH.  E.g.,
# setenv LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:/home/kgold/openssl

# link - for TSS library

# hardening flags for linking shared objects
LNLFLAGS += -shared -Wl,-z,now

# This is an alternative to using the bfd linker on Ubuntu
LNLLIBS += -lcrypto

# link - for applications, TSS path, TSS and OpenSSl libraries

# hardening flags for linking executables
LNAFLAGS += -pie -Wl,-z,now -Wl,-rpath,.

LNALIBS +=  -libmtssutils -libmtss -lcrypto

# shared library

# versioned shared library
LIBTSSVERSIONED=libibmtss.so.0.1

# soname field of the shared library
# which will be made symbolic link to the versioned shared library
# this is used to provide version backward-compatibility information
LIBTSSSONAME=libibmtss.so.0

# symbolic link to the versioned shared library
# this allows linking to the shared library with '-libmtss' 

os := $(shell uname -o)
ifeq ($(os),Cygwin)
  LIBTSS=libibmtss.dll
else
  LIBTSS=libibmtss.so
endif

# TSS utilities shared library

LIBTSSUTILSVERSIONED=libibmtssutils.so.0.1
LIBTSSUTILSSONAME=libibmtssutils.so.0
LIBTSSUTILS=libibmtssutils.so

# executable extension

EXE =

# 


TSS_HEADERS=

# default TSS library

TSS_OBJS = 	tssfile.o 		\
		tsscryptoh.o 		\
		tsscrypto.o 		\
		tssprintcmd.o

TSSUTILS_OBJS = cryptoutils.o	\
		ekutils.o	\
		imalib.o	\
		eventlib.o

# common to all builds

include makefile-common
include makefile-common20

# default build target

all:	$(ALL)

# TSS shared library source

tss.o: 		$(TSS_HEADERS) tss.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss.c
tssauth.o: 	$(TSS_HEADERS) tssauth.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth.c
tssproperties.o: $(TSS_HEADERS) tssproperties.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssproperties.c
tssmarshal.o: 	$(TSS_HEADERS) tssmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssmarshal.c
tsscryptoh.o: 	$(TSS_HEADERS) tsscryptoh.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscryptoh.c
tsscrypto.o: 	$(TSS_HEADERS) tsscrypto.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscrypto.c
tssutils.o: 	$(TSS_HEADERS) tssutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssutils.c
tssfile.o: 	$(TSS_HEADERS) tssfile.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssfile.c
tsssocket.o: 	$(TSS_HEADERS) tsssocket.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsssocket.c
tssdev.o: 	$(TSS_HEADERS) tssdev.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssdev.c
tsstransmit.o: 	$(TSS_HEADERS) tsstransmit.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsstransmit.c
tssresponsecode.o: $(TSS_HEADERS) tssresponsecode.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssresponsecode.c
tssccattributes.o: $(TSS_HEADERS) tssccattributes.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssccattributes.c
fail.o: 	$(TSS_HEADERS) fail.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) fail.c
tssprint.o: 	$(TSS_HEADERS) tssprint.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssprint.c
tssprintcmd.o: 	$(TSS_HEADERS) tssprintcmd.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssprintcmd.c
Unmarshal.o: 	$(TSS_HEADERS) Unmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Unmarshal.c
Commands.o: 	$(TSS_HEADERS) Commands.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Commands.c
CommandAttributeData.o: 	$(TSS_HEADERS) CommandAttributeData.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) CommandAttributeData.c
ntc2lib.o:	$(TSS_HEADERS) ntc2lib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ntc2lib.c
tssntc.o:	$(TSS_HEADERS) tssntc.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssntc.c

# TPM 2.0

tss20.o: 	$(TSS_HEADERS) tss20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss20.c
tssauth20.o: 	$(TSS_HEADERS) tssauth20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth20.c

# TSS utilities shared library source

cryptoutils.o: 	$(TSS_HEADERS) cryptoutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) cryptoutils.c
ekutils.o: 	$(TSS_HEADERS) ekutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ekutils.c
imalib.o: 	$(TSS_HEADERS) imalib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) imalib.c
eventlib.o: 	$(TSS_HEADERS) eventlib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) eventlib.c

# TSS shared library build

$(LIBTSS): 	$(TSS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -Wl,-soname,$(LIBTSSSONAME) -o $(LIBTSSVERSIONED) $(TSS_OBJS) $(LNLLIBS)
		rm -f $(LIBTSSSONAME)
		ln -sf $(LIBTSSVERSIONED) $(LIBTSSSONAME)
		rm -f $(LIBTSS)
		ln -sf $(LIBTSSSONAME) $(LIBTSS)

# TSS utilities shared library

$(LIBTSSUTILS):	$(TSSUTILS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -Wl,-soname,$(LIBTSSUTILSSONAME) -o $(LIBTSSUTILSVERSIONED) $(TSSUTILS_OBJS) $(LNLLIBS)
		rm -f $(LIBTSSSUTILSONAME)
		ln -sf $(LIBTSSUTILSVERSIONED) $(LIBTSSUTILSSONAME)
		rm -f $(LIBTSSUTILS)
		ln -sf $(LIBTSSUTILSSONAME) $(LIBTSSUTILS)

.PHONY:		clean
.PRECIOUS:	%.o

clean:		
		rm -f *.o  *~ 		\
		h*.bin			\
		$(LIBTSSSONAME)		\
		$(LIBTSSVERSIONED) 	\
		$(LIBTSSUTILSSONAME) 	\
		$(LIBTSSUTILSVERSIONED)	\
		$(ALL)
# applications

activatecredential:	tss2/tss.h activatecredential.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) activatecredential.o $(LNALIBS) -o activatecredential
eventextend:		eventextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventextend.o $(LNALIBS) -o eventextend
imaextend:		imaextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) imaextend.o $(LNALIBS) -o imaextend
certify:		tss2/tss.h certify.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) certify.o $(LNALIBS) -o certify
certifycreation:	tss2/tss.h certifycreation.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) certifycreation.o $(LNALIBS) -o certifycreation
changeeps:		tss2/tss.h changeeps.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) changeeps.o $(LNALIBS) -o changeeps
changepps:		tss2/tss.h changepps.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) changepps.o $(LNALIBS) -o changepps
clear:			tss2/tss.h clear.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clear.o $(LNALIBS) -o clear
clearcontrol:		tss2/tss.h clearcontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clearcontrol.o $(LNALIBS) -o clearcontrol
clockrateadjust:	tss2/tss.h clockrateadjust.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clockrateadjust.o $(LNALIBS) -o clockrateadjust
clockset:		tss2/tss.h clockset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clockset.o $(LNALIBS) -o clockset
commit:			tss2/tss.h commit.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) commit.o $(LNALIBS) -o commit
contextload:		tss2/tss.h contextload.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) contextload.o $(LNALIBS) -o contextload
contextsave:		tss2/tss.h contextsave.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) contextsave.o $(LNALIBS) -o contextsave
create:			tss2/tss.h create.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) create.o objecttemplates.o $(LNALIBS) -o create
createloaded:		tss2/tss.h createloaded.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createloaded.o objecttemplates.o $(LNALIBS) -o createloaded
createprimary:		tss2/tss.h createprimary.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createprimary.o objecttemplates.o $(LNALIBS) -o createprimary
dictionaryattacklockreset:		tss2/tss.h dictionaryattacklockreset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) dictionaryattacklockreset.o $(LNALIBS) -o dictionaryattacklockreset
dictionaryattackparameters:		tss2/tss.h dictionaryattackparameters.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) dictionaryattackparameters.o $(LNALIBS) -o dictionaryattackparameters
duplicate:		tss2/tss.h duplicate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) duplicate.o $(LNALIBS) -o duplicate 
eccparameters:		tss2/tss.h eccparameters.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eccparameters.o $(LNALIBS) -o eccparameters 
ecephemeral:		tss2/tss.h ecephemeral.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ecephemeral.o $(LNALIBS) -o ecephemeral 
encryptdecrypt:		tss2/tss.h encryptdecrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) encryptdecrypt.o $(LNALIBS) -o encryptdecrypt	
eventsequencecomplete:	tss2/tss.h eventsequencecomplete.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventsequencecomplete.o $(LNALIBS) -o eventsequencecomplete	
evictcontrol:		tss2/tss.h evictcontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) evictcontrol.o $(LNALIBS) -o evictcontrol	
flushcontext:		tss2/tss.h flushcontext.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) flushcontext.o $(LNALIBS) -o flushcontext
getcommandauditdigest:	tss2/tss.h getcommandauditdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcommandauditdigest.o $(LNALIBS) -o getcommandauditdigest
getcapability:		tss2/tss.h getcapability.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcapability.o $(LNALIBS) -o getcapability
getrandom:		tss2/tss.h getrandom.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getrandom.o $(LNALIBS) -o getrandom
gettestresult:		tss2/tss.h gettestresult.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) gettestresult.o $(LNALIBS) -o gettestresult
getsessionauditdigest:	tss2/tss.h getsessionauditdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getsessionauditdigest.o $(LNALIBS) -o getsessionauditdigest
gettime:		tss2/tss.h gettime.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) gettime.o $(LNALIBS) -o gettime
hashsequencestart:	tss2/tss.h hashsequencestart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hashsequencestart.o $(LNALIBS) -o hashsequencestart
hash:			tss2/tss.h hash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hash.o $(LNALIBS) -o hash
hierarchycontrol:	tss2/tss.h hierarchycontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hierarchycontrol.o $(LNALIBS) -o hierarchycontrol
hierarchychangeauth:	tss2/tss.h hierarchychangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hierarchychangeauth.o $(LNALIBS) -o hierarchychangeauth
hmac:			tss2/tss.h hmac.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hmac.o $(LNALIBS) -o hmac
hmacstart:		tss2/tss.h hmacstart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hmacstart.o $(LNALIBS) -o hmacstart
import:			tss2/tss.h import.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) import.o $(LNALIBS) -o import
importpem:		tss2/tss.h importpem.o objecttemplates.o $(L $(LIBTSSUTILS)IBTSS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) importpem.o objecttemplates.o $(LNALIBS) -o importpem
load:			tss2/tss.h load.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) load.o $(LNALIBS) -o load
loadexternal:		tss2/tss.h loadexternal.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) loadexternal.o $(LNALIBS) -o loadexternal
makecredential:		tss2/tss.h makecredential.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makecredential.o $(LNALIBS) -o makecredential
nvcertify:		tss2/tss.h nvcertify.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvcertify.o $(LNALIBS) -o nvcertify
nvchangeauth:		tss2/tss.h nvchangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvchangeauth.o $(LNALIBS) -o nvchangeauth
nvdefinespace:		tss2/tss.h nvdefinespace.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvdefinespace.o $(LNALIBS) -o nvdefinespace
nvextend:		tss2/tss.h nvextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvextend.o $(LNALIBS) -o nvextend
nvglobalwritelock:	tss2/tss.h nvglobalwritelock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvglobalwritelock.o $(LNALIBS) -o nvglobalwritelock
nvincrement:		tss2/tss.h nvincrement.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvincrement.o $(LNALIBS) -o nvincrement
nvread:			tss2/tss.h nvread.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvread.o $(LNALIBS) -o nvread
nvreadlock:		tss2/tss.h nvreadlock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadlock.o $(LNALIBS) -o nvreadlock
nvreadpublic:		tss2/tss.h nvreadpublic.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadpublic.o $(LNALIBS) -o nvreadpublic
nvsetbits:		tss2/tss.h nvsetbits.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvsetbits.o $(LNALIBS) -o nvsetbits
nvundefinespace:	tss2/tss.h nvundefinespace.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvundefinespace.o $(LNALIBS) -o nvundefinespace
nvundefinespacespecial:	tss2/tss.h nvundefinespacespecial.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvundefinespacespecial.o $(LNALIBS) -o nvundefinespacespecial
nvwrite:		tss2/tss.h nvwrite.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwrite.o $(LNALIBS) -o nvwrite
nvwritelock:		tss2/tss.h nvwritelock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritelock.o $(LNALIBS) -o nvwritelock
objectchangeauth:	tss2/tss.h objectchangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) objectchangeauth.o $(LNALIBS) -o objectchangeauth
pcrallocate: 		tss2/tss.h pcrallocate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrallocate.o $(LNALIBS) -o pcrallocate
pcrevent: 		tss2/tss.h pcrevent.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrevent.o $(LNALIBS) -o pcrevent
pcrextend: 		tss2/tss.h pcrextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrextend.o $(LNALIBS) -o pcrextend
pcrread: 		tss2/tss.h pcrread.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrread.o $(LNALIBS) -o pcrread
pcrreset: 		tss2/tss.h pcrreset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrreset.o $(LNALIBS) -o pcrreset
policyauthorize:	tss2/tss.h policyauthorize.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthorize.o $(LNALIBS) -o policyauthorize
policyauthvalue:	tss2/tss.h policyauthvalue.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthvalue.o $(LNALIBS) -o policyauthvalue
policycommandcode:	tss2/tss.h policycommandcode.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycommandcode.o $(LNALIBS) -o policycommandcode
policycphash:		tss2/tss.h policycphash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycphash.o $(LNALIBS) -o policycphash
policynamehash:		tss2/tss.h policynamehash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynamehash.o $(LNALIBS) -o policynamehash
policycountertimer:	tss2/tss.h policycountertimer.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycountertimer.o $(LNALIBS) -o policycountertimer
policyduplicationselect:	tss2/tss.h policyduplicationselect.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyduplicationselect.o $(LNALIBS) -o policyduplicationselect
policygetdigest:	tss2/tss.h policygetdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policygetdigest.o $(LNALIBS) -o policygetdigest
policymaker:		tss2/tss.h policymaker.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policymaker.o $(LNALIBS) -o policymaker
policymakerpcr:		tss2/tss.h policymakerpcr.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policymakerpcr.o $(LNALIBS) -o policymakerpcr
policyauthorizenv:	tss2/tss.h policyauthorizenv.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthorizenv.o $(LNALIBS) -o policyauthorizenv
policynv:		tss2/tss.h policynv.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynv.o $(LNALIBS) -o policynv
policynvwritten:	tss2/tss.h policynvwritten.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynvwritten.o $(LNALIBS) -o policynvwritten
policyor:		tss2/tss.h policyor.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyor.o $(LNALIBS) -o policyor
policypassword:		tss2/tss.h policypassword.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policypassword.o $(LNALIBS) -o policypassword
policypcr:		tss2/tss.h policypcr.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policypcr.o $(LNALIBS) -o policypcr
policyrestart:		tss2/tss.h policyrestart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyrestart.o $(LNALIBS) -o policyrestart
policysigned:		tss2/tss.h policysigned.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policysigned.o $(LNALIBS) -o policysigned
policysecret:		tss2/tss.h policysecret.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policysecret.o $(LNALIBS) -o policysecret
policytemplate:		tss2/tss.h policytemplate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policytemplate.o $(LNALIBS) -o policytemplate
policyticket:		tss2/tss.h policyticket.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyticket.o $(LNALIBS) -o policyticket
quote:			tss2/tss.h quote.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) quote.o $(LNALIBS) -o quote
powerup:		tss2/tss.h powerup.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) powerup.o $(LNALIBS) -o powerup
readclock:		tss2/tss.h readclock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) readclock.o $(LNALIBS) -o readclock
readpublic:		tss2/tss.h readpublic.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) readpublic.o $(LNALIBS) -o readpublic
returncode:		tss2/tss.h returncode.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) returncode.o $(LNALIBS) -o returncode
rewrap:			tss2/tss.h rewrap.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rewrap.o $(LNALIBS) -o rewrap
rsadecrypt: 		tss2/tss.h rsadecrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rsadecrypt.o $(LNALIBS) -o rsadecrypt
rsaencrypt: 		tss2/tss.h rsaencrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rsaencrypt.o $(LNALIBS) -o rsaencrypt
sequenceupdate:		tss2/tss.h sequenceupdate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sequenceupdate.o $(LNALIBS) -o sequenceupdate
sequencecomplete:	tss2/tss.h sequencecomplete.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sequencecomplete.o $(LNALIBS) -o sequencecomplete
setprimarypolicy:	tss2/tss.h setprimarypolicy.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) setprimarypolicy.o $(LNALIBS) -o setprimarypolicy
shutdown:		tss2/tss.h shutdown.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) shutdown.o $(LNALIBS) -o shutdown
sign:			tss2/tss.h sign.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sign.o $(LNALIBS) -o sign
startauthsession:	tss2/tss.h startauthsession.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startauthsession.o $(LNALIBS) -o startauthsession
startup:		tss2/tss.h startup.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startup.o $(LNALIBS) -o startup
stirrandom:		tss2/tss.h stirrandom.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) stirrandom.o $(LNALIBS) -o stirrandom
unseal:			tss2/tss.h unseal.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) unseal.o $(LNALIBS) -o unseal
verifysignature:	tss2/tss.h verifysignature.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) verifysignature.o $(LNALIBS) -o verifysignature
zgen2phase:		tss2/tss.h zgen2phase.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) zgen2phase.o $(LNALIBS) -o zgen2phase
signapp:		tss2/tss.h signapp.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) signapp.o $(LNALIBS) -o signapp
writeapp:		tss2/tss.h writeapp.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) writeapp.o $(LNALIBS) -o writeapp
timepacket:		tss2/tss.h timepacket.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) timepacket.o $(LNALIBS) -o timepacket
createek:		createek.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createek.o $(LNALIBS) -o createek
createekcert:		createekcert.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createekcert.o $(LNALIBS) -o createekcert
tpm2pem:		tpm2pem.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpm2pem.o $(LNALIBS) -o tpm2pem
tpmpublic2eccpoint:	tpmpublic2eccpoint.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpmpublic2eccpoint.o $(LNALIBS) -o tpmpublic2eccpoint
ntc2getconfig:		ntc2getconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2getconfig.o $(LNALIBS) -o ntc2getconfig
ntc2preconfig:		ntc2preconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2preconfig.o $(LNALIBS) -o ntc2preconfig
ntc2lockconfig:		ntc2lockconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2lockconfig.o $(LNALIBS) -o ntc2lockconfig

# for applications, not for TSS library

%.o:		%.c tss2/tss.h 
		$(CC) $(CCFLAGS) $(CCAFLAGS) $< -o $@

