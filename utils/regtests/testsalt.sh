#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testsalt.sh 1277 2018-07-23 20:30:23Z kgoldman $			#
#										#
# (c) Copyright IBM Corporation 2015 - 2018					#
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

for ASY in "-rsa" "-ecc nistp256"
do
    for HALG in ${ITERATE_ALGS}
    do

	# In general a storage key can be used.  A decryption key is
	# used here because the hash algorithm doesn't have to match
	# that of the parent.

	echo "Create a ${ASY} ${HALG} storage key under the primary key "
	${PREFIX}create -hp 80000000 -nalg ${HALG} -halg ${HALG} ${ASY} -deo -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 222 > run.out
	checkSuccess $?

	echo "Load the ${ASY} storage key 80000001 under the primary key"
	${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	checkSuccess $?

	echo "Start a ${ASY} salted HMAC auth session"
	${PREFIX}startauthsession -se h -hs 80000001 > run.out
	checkSuccess $?

	echo "Create a signing key using the salt"
	${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
	checkSuccess $?

	echo "Flush the storage key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done
done

echo ""
echo "Salt Session - Load External"
echo ""

echo "Create RSA and ECC key pairs in PEM format using openssl"
  
openssl genrsa -out tmpkeypairrsa.pem -aes256 -passout pass:rrrr 2048 > run.out
openssl ecparam -name prime256v1 -genkey -noout -out tmpkeypairecc.pem > run.out

echo "Convert key pair to plaintext DER format"

openssl rsa -inform pem -outform der -in tmpkeypairrsa.pem -out tmpkeypairrsa.der -passin pass:rrrr > run.out
openssl ec -inform pem -outform der -in tmpkeypairecc.pem -out tmpkeypairecc.der -passin pass:rrrr > run.out

for HALG in ${ITERATE_ALGS}
do

    echo "Load the RSA openssl key pair in the NULL hierarchy 80000001 - ${HALG}"
    ${PREFIX}loadexternal -rsa -halg ${HALG} -st -ider tmpkeypairrsa.der > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

for HALG in ${ITERATE_ALGS}
do

    echo "Load the ECC openssl key pair in the NULL hierarchy 80000001 - ${HALG}"
    ${PREFIX}loadexternal -ecc -halg ${HALG} -st -ider tmpkeypairecc.der > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - CreatePrimary storage key"
echo ""

for HALG in ${ITERATE_ALGS}
do
    
    echo "Create a primary storage key - $HALG"
    ${PREFIX}createprimary -nalg $HALG -hi p > run.out
    checkSuccess $?

    echo "Start a salted HMAC auth session"
    ${PREFIX}startauthsession -se h -hs 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key using the salt"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Salt Session - CreatePrimary RSA key"
echo ""

for HALG in ${ITERATE_ALGS}
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
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp sto > run.out
checkSuccess $?

echo "Make the storage key persistent"
${PREFIX}evictcontrol -ho 80000001 -hp 81800000 -hi p > run.out
checkSuccess $?

echo "Start a salted HMAC auth session"
${PREFIX}startauthsession -se h -hs 81800000 > run.out
checkSuccess $?

echo "Create a signing key using the salt"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
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
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp sto > run.out
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
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
checkSuccess $?

echo "Flush the context loaded key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Salt Audit Session - PCR Read, Read Public, NV Read Public"
echo ""

echo "Load the storage key at 80000001"
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a salted HMAC auth session"
${PREFIX}startauthsession -se h -hs 80000001 > run.out
checkSuccess $?

echo "PCR read with salted audit session"
${PREFIX}pcrread -ha 16 -se0 02000000 81 > run.out
checkSuccess $?

echo "Read public with salted audit session"
${PREFIX}readpublic -ho 80000001 -se0 02000000 81 > run.out
checkSuccess $?

echo "NV define space"
${PREFIX}nvdefinespace -ha 01000000 -hi p > run.out
checkSuccess $?

echo "NV Read public with salted audit session"
${PREFIX}nvreadpublic -ha 01000000 -se0 02000000 81 > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the salt session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "NV undefine space"
${PREFIX}nvundefinespace -ha 01000000 -hi p > run.out
checkSuccess $?

rm -f tmpkeypairrsa.pem
rm -f tmpkeypairecc.pem
rm -f tmpkeypairrsa.der
rm -f tmpkeypairecc.der
# ${PREFIX}getcapability -cap 1 -pr 80000000

