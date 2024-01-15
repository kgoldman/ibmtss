#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2023					#
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

# openssl keys to use in this file

echo ""
echo "Test RSA"
echo ""

# mbedtls (actually only certain versions) appears to only support the legacy PEM format
# -----BEGIN RSA PRIVATE KEY-----
# and not the PKCS8 format
# -----BEGIN ENCRYPTED PRIVATE KEY-----
#

echo "Generate the encryption keys with openssl"
if   [ ${CRYPTOLIBRARY} == "openssl" ]; then

    for BITS in 2048 3072
    do

	echo "Generate the RSA $BITS encryption key with openssl"
	openssl genpkey -out tmpkeypairrsa${BITS}.pem -outform pem -aes-256-cbc -algorithm rsa -pkeyopt rsa_keygen_bits:${BITS} -pass pass:rrrr > run.out 2>&1

	echo "Convert key pair to plaintext DER format"
	openssl pkey -inform pem -in tmpkeypairrsa${BITS}.pem -outform der -out tmpkeypairrsa${BITS}.der -passin pass:rrrr > run.out 2>&1

	echo "Convert ${BITS} keypair to public key"
	openssl pkey -inform pem -outform pem -in tmpkeypairrsa${BITS}.pem -passin pass:rrrr -pubout -out tmppubkey${BITS}.pem

    done


# The following worked up to Openssl 3.0.0.  The key generation
# remains here for when mbedtls is updated, but the tests are now
# if'ed out

elif [ ${CRYPTOLIBRARY} == "mbedtls" ]; then

    for BITS in 2048 3072
    do

	echo "Generate the RSA $BITS encryption key with openssl"
	openssl genrsa -out tmpkeypairrsaenc${BITS}.pem -outform pem -aes-256-cbc -algorithm rsa -pkeyopt rsa_keygen_bits:${BITS} -pass:rrrr > run.out 2>&1

	echo "Convert RSA $BITS key pair to plaintext DER format"
	openssl rsa -in tmpkeypairrsaenc${BITS}.pem -passin pass:rrrr -outform der -out tmpkeypairrsa${BITS}.der > run.out 2>&1

	echo "Convert RSA $BITS key pair to plaintext PEM format"
	openssl rsa -in tmpkeypairrsaenc${BITS}.pem -passin pass:rrrr -out tmpkeypairrsadec${BITS}.pem > run.out 2>&1

	echo "Convert RSA $BITS encryption key pair to legacy PEM format"
	openssl rsa -aes128 -in tmpkeypairrsadec${BITS}.pem -out tmpkeypairrsa${BITS}.pem -passout pass:rrrr > run.out 2>&1

    done

else
    echo "Error: crypto library ${CRYPTOLIBRARY} not supported"
    exit 255
fi

echo ""
echo "RSA decryption key"
echo ""

for BITS in 2048 3072
do

    echo "Load the RSA $BITS decryption key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr derrsa${BITS}priv.bin -ipu derrsa${BITS}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "RSA encrypt with the $BITS encryption key"
    ${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin -v > run.out
    checkSuccess $?

    echo "RSA decrypt with the ${BITS} decryption key"
    ${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec -v > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    tail -c 3 dec.bin > tmp.bin
    diff policies/aaa tmp.bin > run.out
    checkSuccess $?

    echo "Flush the $BITS decryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "RSA decryption key to sign with OID"
echo ""

for BITS in 2048 3072
do

    echo "Load the RSA $BITS decryption key"
    ${PREFIX}load -hp 80000000 -ipu derrsa${BITS}pub.bin -ipr derrsa${BITS}priv.bin -pwdp sto > run.out
    checkSuccess $?

    HSIZ=(${ITERATE_ALGS_SIZES})
    HALG=(${ITERATE_ALGS})

    for ((i = 0 ; i < ${ITERATE_ALGS_COUNT} ; i++))
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

    echo "Flush the RSA ${BITS} decryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

if   [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo ""
    echo "Import PEM RSA encryption key"
    echo ""

    echo "Start an HMAC auth session"
    ${PREFIX}startauthsession -se h > run.out
    checkSuccess $?

    for BITS in 2048 3072
    do

	for SESS in "" "-se0 02000000 1"
	do

	echo "Import the $BITS encryption key under the primary key"
	${PREFIX}importpem -hp 80000000 -den -pwdp sto -ipem tmpkeypairrsa${BITS}.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin > run.out
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

    done

    echo "Flush the session"
    ${PREFIX}flushcontext -ha 02000000 > run.out
    checkSuccess $?

    echo ""
    echo "Import PEM RSA encryption key userWithAuth test"
    echo ""

    echo "Import the RSA 2048 encryption key under the primary key 80000000"
    ${PREFIX}importpem -hp 80000000 -den -pwdp sto -ipem tmpkeypairrsa2048.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin > run.out
    checkSuccess $?

    echo "Load the RSA 2048 encryption key 80000001"
    ${PREFIX}load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
    checkSuccess $?

    echo "RSA encrypt with the encryption key"
    ${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    checkSuccess $?

    echo "RSA decrypt with the decryption key and password"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin > run.out
    checkSuccess $?

    echo "Flush the encryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Import the RSA 2048 encryption key under the primary key, userWithAuth false"
    ${PREFIX}importpem -hp 80000000 -si -pwdp sto -ipem tmpkeypairrsa2048.pem -pwdk rrrr -uwa -opu tmppub.bin -opr tmppriv.bin > run.out
    checkSuccess $?

    echo "Load the RSA 2048 encryption key"
    ${PREFIX}load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
    checkSuccess $?

    echo "RSA decrypt with the decryption key and password - should fail"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin > run.out
    checkFailure $?

    echo "Flush the encryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo ""
    echo "Loadexternal DER encryption key"
    echo ""

    for BITS in 2048 3072
    do

	echo "Start an HMAC auth session"
	${PREFIX}startauthsession -se h > run.out
	checkSuccess $?

	for SESS in "" "-se0 02000000 1"
	do

	    echo "Load the openssl key pair in the NULL hierarchy 80000001"
	    ${PREFIX}loadexternal -den -ider tmpkeypairrsa${BITS}.der -pwdk rrrr > run.out
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

    done

fi

echo ""
echo "TPM key, Encrypt with OpenSSL OAEP, decrypt with TPM"
echo ""

for BITS in 2048 3072
do

    echo "Create ${BITS} OAEP encryption key"
    ${PREFIX}create -hp 80000000 -pwdp sto -deo -kt f -kt p -rsa ${BITS} -halg sha256 -opr tmpprivkey.bin -opu tmppubkey.bin -opem tmppubkey.pem > run.out
    checkSuccess $?

    echo "Load ${BITS} encryption key at 80000001"
    ${PREFIX}load -hp 80000000 -pwdp sto -ipr tmpprivkey.bin -ipu tmppubkey.bin  > run.out
    checkSuccess $?

    echo "Encrypt using OpenSSL and the PEM public key"
    openssl pkeyutl -encrypt -inkey tmppubkey.pem -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in policies/aaa -out enc.bin > run.out 2>&1
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

done

echo ""
echo "Child RSA decryption key RSAES"
echo ""

echo "Create RSAES encryption key"
${PREFIX}create -hp 80000000 -pwdp sto -dee -opr deepriv.bin -opu deepub.bin > run.out
checkSuccess $?

echo "Load encryption key at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipr deepriv.bin -ipu deepub.bin > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary RSA decryption key RSAES"
echo ""

echo "Create Primary RSAES encryption key"
${PREFIX}createprimary -hi p -dee -halg sha256 -opem tmppubkey.pem > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary Create Loaded RSA decryption key RSAES"
echo ""

echo "CreateLoaded primary key, storage parent 80000001"
${PREFIX}createloaded -hp 40000001 -dee > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

if   [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo ""
    echo "OpenSSL key, Encrypt with OpenSSL, decrypt with TPM"
    echo ""

    for BITS in 2048 3072
    do

	for SCHEME in oaep pkcs1
	do

	    echo "Encrypt using OpenSSL ${SCHEME} and the ${BITS} PEM public key"
	    # The rsa_oaep_md:sha256 parameter is ignored for pkcs1 only after openssl 3.x
	    if [ ${SCHEME} == "pkcs1" ]; then
		openssl pkeyutl -encrypt -inkey tmppubkey${BITS}.pem -pubin -pkeyopt rsa_padding_mode:${SCHEME}  -in policies/aaa -out enc.bin > run.out 2>&1
	    else
		openssl pkeyutl -encrypt -inkey tmppubkey${BITS}.pem -pubin -pkeyopt rsa_padding_mode:${SCHEME} -pkeyopt rsa_oaep_md:sha256 -in policies/aaa -out enc.bin > run.out 2>&1
	    fi
	    checkSuccess $?

	    echo "Loadexternal the openssl ${BITS} ${SCHEME} key pair in the NULL hierarchy 80000001"
	    ${PREFIX}loadexternal -den -scheme rsa${SCHEME} -ider tmpkeypairrsa${BITS}.der -pwdk rrrr > run.out
	    checkSuccess $?

	    echo "Decrypt using TPM key at 80000001"
	    ${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin > run.out
	    checkSuccess $?

	    echo "Verify the decrypt result"
	    diff policies/aaa dec.bin > run.out
	    checkSuccess $?

	    echo "Flush the encryption key"
	    ${PREFIX}flushcontext -ha 80000001 > run.out
	    checkSuccess $?

	done
    done
fi

  # cleanup

rm -f tmp.bin
rm -f enc.bin
rm -f dec.bin
rm -f deepriv.bin
rm -f deepub.bin
rm -f tmpmsg.bin
rm -f tmpdig.bin
rm -f tmpsig.bin
for BITS in 2048 3072
do
    rm -f tmpkeypairrsa${BITS}.der
    rm -f tmpkeypairrsa${BITS}.pem
    rm -f tmpkeypairrsaenc${BITS}.pem
    rm -f tmpkeypairrsadec${BITS}.pem
    rm -f tmppubkey${BITS}.bin
    rm -f tmppubkey${BITS}.pem
done
rm -f tmppubkey.pem
rm -f tmppubkey.bin
rm -f tmpprivkey.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

# ${PREFIX}flushcontext -ha 80000001
