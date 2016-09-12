#################################################################################
#										#
#			Windows MinGW TPM2 Makefile				#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile.mak 684 2016-07-18 21:22:01Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2015.						#
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

CC = "c:/program files/mingw/bin/gcc.exe"

# compile - common flags for TSS library and applications

CCFLAGS = 					\
	-DTPM_WINDOWS				\
	-I"c:/program files/MinGW/include"	\
	-I"c:/program files/openssl/include"	\
	-I. -I../src

# link - common flags flags TSS library and applications

LNFLAGS =					\
	-D_MT					\
	-DTPM_WINDOWS				\
	-I"c:/program files/MinGW/include"	\
	-I"c:/program files/openssl/include"	\
	-I.

# link - for TSS library

LNLFLAGS = 

# link - for applications, TSS path, TSS and OpenSSl libraries

LNAFLAGS = 

LNLIBS = 	"c:/program files/openssl/lib/mingw/libeay32.a" \
		"c:/program files/openssl/lib/mingw/ssleay32.a" \
		"c:/program files/MinGW/lib/libws2_32.a"

# executable extension

EXE=.exe

# shared library

LIBTSS=libtss.dll

include makefile-common

# Uncomment for TBSI

# CCFLAGS +=	-DTPM_WINDOWS_TBSI		\
# 		-DTPM_WINDOWS_TBSI_WIN8		\
# 		-D_WIN32_WINNT=0x0600

# TSS_OBJS += tsstbsi.o 

# LNLIBS += C:\PROGRA~2\WI3CF2~1\8.0\Lib\win8\um\x86\Tbs.lib
# #LNLIBS += c:/progra~1/Micros~2/Windows/v7.1/lib/Tbs.lib

# default build target

all:	$(ALL)

# TSS library source shared with TPM

Commands.o: 			../src/Commands.c
				$(CC) $(CCFLAGS) ../src/Commands.c
CommandCodeAttributes.o: 	../src/CommandCodeAttributes.c
				$(CC) $(CCFLAGS) ../src/CommandCodeAttributes.c
CpriHash.o: 			../src/CpriHash.c
				$(CC) $(CCFLAGS) ../src/CpriHash.c
CpriSym.o: 			../src/CpriSym.c
				$(CC) $(CCFLAGS) ../src/CpriSym.c

# TSS shared library build

$(LIBTSS): 	$(TSS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -shared -o $(LIBTSS) $(TSS_OBJS) \
		-Wl,--out-implib,libtss.a $(LNLIBS)

.PHONY:		clean
.PRECIOUS:	%.o

clean:		
		rm -f *.o  *~ 	\
		$(LIBTSS)	\
		$(ALL)

eventextend.exe:	eventextend.o eventlib.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -ltss $< -o $@ applink.o eventlib.o $(LNLIBS) $(LIBTSS) 

createek.exe:	createek.o ekutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -ltss $< -o $@ applink.o ekutils.o $(LNLIBS) $(LIBTSS)

pprovision.exe:	pprovision.o ekutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -ltss $< -o $@ applink.o ekutils.o $(LNLIBS) $(LIBTSS)

%.exe:		%.o applink.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -ltss $< -o $@ applink.o $(LNLIBS) $(LIBTSS)

%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@
