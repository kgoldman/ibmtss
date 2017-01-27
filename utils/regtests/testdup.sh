#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testdup.sh 921 2017-01-23 15:56:08Z kgoldman $		#
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

# 80000001 K1 storage key
# 80000002 K2 signing key to be duplicated
# 80000002 K2 duplicated
# 03000000 policy session

# policy
# be f5 6b 8c 1c c8 4e 11 ed d7 17 52 8d 2c d9 93 
# 56 bd 2b bf 8f 01 52 09 c3 f8 4a ee ab a8 e8 a2 

# used for the name in rewrap

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi

echo ""
echo "Duplication"
echo ""

for ENC in "" "-salg aes -ik tmprnd.bin"
do 
    for HALG in sha1 sha256 sha384
    do

	echo "Create a signing key K2 under the primary key, with policy"
	${PREFIX}create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccduplicate.bin > run.out
	checkSuccess $?

	echo "Load the storage key K1"
	${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
	checkSuccess $?

	echo "Load the signing key K2"
	${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
	checkSuccess $?

	echo "Sign a digest, $HALG"
	${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig  > run.out
	checkSuccess $?

	echo "Verify the signature, $HALG"
	${PREFIX}verifysignature -hk 80000002 -halg $HALG -if policies/aaa -is tmpsig.bin > run.out
	checkSuccess $?

	echo "Start a policy session"
	${PREFIX}startauthsession -se p > run.out
	checkSuccess $?

	echo "Policy command code, duplicate"
	${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
	checkSuccess $?

	echo "Get policy digest"
	${PREFIX}policygetdigest -ha 03000000 > run.out 
	checkSuccess $?

	echo "Get random AES encryption key"
	${PREFIX}getrandom -by 16 -of tmprnd.bin > run.out 
	checkSuccess $?

	echo "Duplicate K2 under K1, ${ENC}"
	${PREFIX}duplicate -ho 80000002 -pwdo sig -hp 80000001 -od tmpdup.bin -oss tmpss.bin ${ENC} -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Flush the original K2 to free object slot for import"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Import K2 under K1, ${ENC}"
	${PREFIX}import -hp 80000001 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin ${ENC} -opr tmppriv.bin > run.out
	checkSuccess $?

	echo "Sign under K2, $HALG - should fail"
	${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
	checkFailure $?

	echo "Load the duplicated signing key K2"
	${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	checkSuccess $?

	echo "Sign using duplicated K2, $HALG"
	${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
	checkSuccess $?

	echo "Verify the signature, $HALG"
	${PREFIX}verifysignature -hk 80000002 -halg $HALG -if policies/aaa -is tmpsig.bin > run.out
	checkSuccess $?

	echo "Flush the duplicated K2"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Flush the parent K1"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Flush the session"
	${PREFIX}flushcontext -ha 03000000 > run.out
	checkSuccess $?

    done
done

echo ""
echo "Import PEM RSA"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do
    for HALG in sha1 sha256
    do

	echo "Import the signing key under the primary key ${HALG}"
	${PREFIX}importpem -hp 80000000 -pwdp pps -ipem tmpprivkey.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg ${HALG} > run.out
	checkSuccess $?

	echo "Load the TPM signing key"
	${PREFIX}load -hp 80000000 -pwdp pps -ipu tmppub.bin -ipr tmppriv.bin > run.out
	checkSuccess $?

	echo "Sign the message ${HALG} ${SESS}"
	${PREFIX}sign -hk 80000001 -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg ${HALG} ${SESS} > run.out
	checkSuccess $?

	echo "Verify the signature ${HALG}"
	${PREFIX}verifysignature -hk 80000001 -if policies/aaa -is tmpsig.bin -halg ${HALG} > run.out
	checkSuccess $?

	echo "Flush the signing key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

   done
done

echo ""
echo "Import PEM EC "
echo ""

echo "generate the signing key with openssl"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -aes256 -passout pass:rrrr -text > tmpecprivkey.pem

for SESS in "" "-se0 02000000 1"
do
    for HALG in sha1 sha256
    do

	echo "Import the signing key under the primary key ${HALG}"
	${PREFIX}importpem -hp 80000000 -pwdp pps -ipem tmpecprivkey.pem -ecc -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg ${HALG} > run.out
	checkSuccess $?

	echo "Load the TPM signing key"
	${PREFIX}load -hp 80000000 -pwdp pps -ipu tmppub.bin -ipr tmppriv.bin > run.out
	checkSuccess $?

	echo "Sign the message ${HALG} ${SESS}"
	${PREFIX}sign -hk 80000001 -ecc -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg ${HALG} ${SESS} > run.out
	checkSuccess $?

	echo "Verify the signature ${HALG}"
	${PREFIX}verifysignature -hk 80000001 -ecc -if policies/aaa -is tmpsig.bin -halg ${HALG} > run.out
	checkSuccess $?

	echo "Flush the signing key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

   done
done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Rewrap"
echo ""

# duplicate object O1 to K1 (the outer wrapper, knows inner wrapper)
# rewrap O1 from K1 to K2 (does not know inner wrapper)
# import O1 to K2 (knows inner wrapper)

# 03000000 policy session for duplicate
    
# at TPM 1, duplicate object to K1 outer wrapper, AES wrapper

echo "Create a storage key K2"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmpk2priv.bin -opu tmpk2pub.bin -pwdp pps -pwdk k2 > run.out
checkSuccess $?

echo "Load the storage key K1 80000001 public key "
${PREFIX}loadexternal -hi p -ipu storepub.bin > run.out
checkSuccess $?

echo "Create a signing key O1 with policy"
${PREFIX}create -hp 80000000 -si -opr tmpsignpriv.bin -opu tmpsignpub.bin -pwdp pps -pwdk sig -pol policies/policyccduplicate.bin > run.out
checkSuccess $?

echo "Load the signing key O1 80000002 under the primary key"
${PREFIX}load -hp 80000000 -ipr tmpsignpriv.bin -ipu tmpsignpub.bin -pwdp pps > run.out
checkSuccess $?

echo "Save the signing key O1 name"
cp ${TPM_DATA_DIR}/h80000002.bin tmpo1name.bin

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code, duplicate"
${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
checkSuccess $?

echo "Get random AES encryption key"
${PREFIX}getrandom -by 16 -of tmprnd.bin > run.out
checkSuccess $?

echo "Duplicate O1 80000002 under K1 80000001 outer wrapper, using AES inner wrapper"
${PREFIX}duplicate -ho 80000002 -pwdo sig -hp 80000001 -ik tmprnd.bin -od tmpdup.bin -oss tmpss.bin -salg aes -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush signing key O1 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush storage key K1 80000001 public key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# at TPM 2

echo "Load storage key K1 80000001 public and private key"
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
checkSuccess $?

echo "Load storage key K2 80000002 public key"
${PREFIX}loadexternal -hi p -ipu tmpk2pub.bin > run.out
checkSuccess $?

echo "Rewrap O1 from K1 80000001 to K2 80000002 "
${PREFIX}rewrap -ho 80000001 -hn 80000002 -pwdo sto -id tmpdup.bin -in tmpo1name.bin -iss tmpss.bin -od tmpdup.bin -oss tmpss.bin > run.out
checkSuccess $?

echo "Flush old key K1 80000001"
${PREFIX}flushcontext -ha 80000002 > run.out 
checkSuccess $?

echo "Flush new key K2 80000002 public key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

# at TPM 3

echo "Load storage key K2 80000001 public key"
${PREFIX}load -hp 80000000 -ipr tmpk2priv.bin -ipu tmpk2pub.bin -pwdp pps > run.out
checkSuccess $?

echo "Import rewraped O1 to K2"
${PREFIX}import -hp 80000001 -pwdp k2 -ipu tmpsignpub.bin -id tmpdup.bin -iss tmpss.bin -salg aes -ik tmprnd.bin -opr tmpsignpriv3.bin > run.out
checkSuccess $?

echo "Load the imported signing key O1 80000002 under K2 80000001"
${PREFIX}load -hp 80000001 -ipr tmpsignpriv3.bin -ipu tmpsignpub.bin -pwdp k2 > run.out
checkSuccess $?

echo "Sign using duplicated K2"
${PREFIX}sign -hk 80000002  -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Flush storage key K2 80000001"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush signing key O1 80000002"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

rm -f tmpo1name.bin
rm -f tmpsignpriv.bin
rm -f tmpsignpub.bin
rm -f tmprnd.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmpsignpriv3.bin
rm -f tmpsig.bin
rm -f tmpk2priv.bin
rm -f tmpk2pub.bin
rm -f tmposs.bin 
rm -f tmpprivkey.pem
rm -f tmpecprivkey.pem
rm -f tmppub.bin
rm -f tmppriv.bin

# ${PREFIX}flushcontext -ha 80000001
# ${PREFIX}flushcontext -ha 80000002
# ${PREFIX}flushcontext -ha 03000000

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 03000000
