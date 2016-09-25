#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testsalt.sh 751 2016-09-22 20:00:12Z kgoldman $			#
#										#
# (c) Copyright IBM Corporation 2015						#
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

echo ""
echo "Salt Session - Load"
echo ""

for HALG in sha1 sha256 sha384
do

    echo "Create a ${HALG} storage key under the primary key "
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -halg ${HALG} -deo -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 222 > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - Load External"
echo ""

echo "Create a key pair in PEM format using openssl"
  
openssl genrsa -out tmpkeypair.pem -aes256 -passout pass:rrrr 2048 > run.out

echo "Convert key pair to plaintext DER format"

openssl rsa -inform pem -outform der -in tmpkeypair.pem -out tmpkeypair.der -passin pass:rrrr > run.out

for HALG in sha1 sha256
do

    echo "Load the openssl key pair in the NULL hierarchy - $HALG"
    ${PREFIX}loadexternal -halg $HALG -st -ider tmpkeypair.der > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - CreatePrimary storage key"
echo ""

for HALG in sha1 sha256
do
    
    echo "Create a primary storage key - $HALG"
    ${PREFIX}createprimary -nalg $HALG -hi p > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - CreatePrimary RSA key"
echo ""

for HALG in sha1 sha256
do
    
    echo "Create a primary RSA key - $HALG"
    ${PREFIX}createprimary -nalg $HALG -halg $HALG -hi p -deo > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a primary HMAC key using the salt"
    ${PREFIX}createprimary -kh -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the HMAC key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the RSA key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - EvictControl"
echo ""

echo "Load the storage key"
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
checkSuccess $?

echo "Make the storage key persistent"
${PREFIX}evictcontrol -ho 80000001 -hp 81800000 -hi p > run.out
checkSuccess $?

echo "Start a salted HMAC auth session"
${PREFIX}startauthsession -se h -hs 81800000 > run.out
checkSuccess $?

echo "Create a signing key using the salt"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 333 -se0 02000000 0 > run.out
checkSuccess $?

echo "Flush the storage key from transient memory"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the storage key from persistent memory"
${PREFIX}evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out
checkSuccess $?

echo ""
echo "Salt Session - ContextSave and ContextLoad"
echo ""

echo "Load the storage key at 80000001"
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
checkSuccess $?

echo "Save context for the key at 80000001"
${PREFIX}contextsave -ha 80000001 -of tmp.bin > run.out
checkSuccess $?

echo "Flush the storage key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Load context, new storage key at 80000001"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Start a salted HMAC auth session"
${PREFIX}startauthsession -se h -hs 80000001 > run.out
checkSuccess $?

echo "Create a signing key using the salt"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk 333 -se0 02000000 0 > run.out
checkSuccess $?

echo "Flush the context loaded key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -f tmpkeypair.pem
rm -f tmpkeypair.der
# ${PREFIX}getcapability -cap 1 -pr 80000000

