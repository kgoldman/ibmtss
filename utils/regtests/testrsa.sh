#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testrsa.sh 1307 2018-08-20 19:43:29Z kgoldman $			#
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
echo "RSA decryption key"
echo ""

echo "Load the decryption key under the primary key"
${PREFIX}load -hp 80000000 -ipr derpriv.bin -ipu derpub.bin -pwdp sto > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the decryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "RSA decryption key to sign with OID"
echo ""

echo "Load the RSA decryption key"
${PREFIX}load -hp 80000000 -ipu derpub.bin -ipr derpriv.bin -pwdp sto > run.out
checkSuccess $?

HALG=(${ITERATE_ALGS})
HSIZ=("20" "32" "48" "64")

for ((i = 0 ; i < 4 ; i++))
do

    echo "Decrypt/Sign with a caller specified OID - ${HALG[i]}"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk dec -ie policies/${HALG[i]}aaa.bin -od tmpsig.bin -oid ${HALG[i]} > run.out
    checkSuccess $?

    echo "Encrypt/Verify - ${HALG[i]}"
    ${PREFIX}rsaencrypt -hk 80000001 -id tmpsig.bin -oe tmpmsg.bin > run.out
    checkSuccess $?

    echo "Verify Result - ${HALG[i]} ${HSIZ[i]} bytes"
    tail -c ${HSIZ[i]} tmpmsg.bin > tmpdig.bin
    diff tmpdig.bin policies/${HALG[i]}aaa.bin > run.out
    checkSuccess $?

done

echo "Flush the RSA signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Import PEM RSA encryption key"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Import the encryption key under the primary key"
    ${PREFIX}importpem -hp 80000000 -den -pwdp sto -ipem tmpprivkey.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin > run.out
    checkSuccess $?

    echo "Load the TPM encryption key"
    ${PREFIX}load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
    checkSuccess $?

    echo "Sign the message ${SESS} - should fail"
    ${PREFIX}sign -hk 80000001 -pwdk rrrr -if policies/aaa -os tmpsig.bin ${SESS} > run.out
    checkFailure $?

    echo "RSA encrypt with the encryption key"
    ${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    checkSuccess $?

    echo "RSA decrypt with the decryption key ${SESS}"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin ${SESS} > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    tail -c 3 dec.bin > tmp.bin
    diff policies/aaa tmp.bin > run.out
    checkSuccess $?

    echo "Flush the encryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Loadexternal DER encryption key"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpkeypair.pem -aes256 -passout pass:rrrr 2048

echo "Convert key pair to plaintext DER format"

openssl rsa -inform pem -outform der -in tmpkeypair.pem -out tmpkeypair.der -passin pass:rrrr > run.out

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Load the openssl key pair in the NULL hierarchy 80000001"
    ${PREFIX}loadexternal -den -ider tmpkeypair.der -pwdk rrrr > run.out
    checkSuccess $?

    echo "RSA encrypt with the encryption key"
    ${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    checkSuccess $?

    echo "RSA decrypt with the decryption key ${SESS}"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin ${SESS} > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    tail -c 3 dec.bin > tmp.bin
    diff policies/aaa tmp.bin > run.out
    checkSuccess $?

    echo "Flush the encryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Encrypt with OpenSSL OAEP, decrypt with TPM"
echo ""

echo "Create OAEP encruption key"
${PREFIX}create -hp 80000000 -pwdp sto -deo -kt f -kt p -halg sha1 -opr tmpprivkey.bin -opu tmppubkey.bin -opem tmppubkey.pem > run.out	
checkSuccess $?

echo "Load encryption key at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipr tmpprivkey.bin -ipu tmppubkey.bin  > run.out
checkSuccess $?

echo "Encrypt using OpenSSL and the PEM public key"
openssl rsautl -oaep -encrypt -inkey tmppubkey.pem -pubin -in policies/aaa -out enc.bin > run.out
checkSuccess $?

echo "Decrypt using TPM key at 80000001"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
diff policies/aaa dec.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -f tmpmsg.bin
rm -f tmpdig.bin
rm -f tmpsig.bin
rm -f tmpprivkey.bin 
rm -f tmppubkey.bin
rm -f tmppubkey.pem
rm -f tmpprivkey.pem
rm -f tmpkeypair.pem
rm -f tmpkeypair.der

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

# ${PREFIX}flushcontext -ha 80000001
