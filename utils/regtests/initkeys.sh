#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2020					#
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

echo -n "1234567890123456" > msg.bin
touch zero.bin

# try to undefine any NV index left over from a previous test.  Do not check for errors.
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
${PREFIX}nvundefinespace -hi p -ha 01000000 -pwdp ppp > run.out
${PREFIX}nvundefinespace -hi p -ha 01000001 > run.out
${PREFIX}nvundefinespace -hi o -ha 01000002 > run.out
${PREFIX}nvundefinespace -hi o -ha 01000003 > run.out
# same for persistent objects
${PREFIX}evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out

echo ""
echo "Initialize Regression Test Keys"
echo ""

# Create a platform primary RSA storage key
initprimary

SHALG=(sha256 sha384)
BITS=(2048 3072)

for ((i = 0 ; i < 2 ; i++))
do

    echo "Create an RSA ${BITS[i]} ${SHALG[i]} storage key under the primary key"
    ${PREFIX}create -hp 80000000 -rsa ${BITS[i]} -halg ${SHALG[i]} -st -kt f -kt p -pol policies/policycccreate-auth.bin -opr storersa${BITS[i]}priv.bin -opu storersa${BITS[i]}pub.bin -tk storersa${BITS[i]}tk.bin -ch storersa${BITS[i]}ch.bin -pwdp sto -pwdk sto > run.out
    checkSuccess $?

    echo "Create an RSA ${BITS[i]} ${SHALG[i]} unrestricted signing key under the primary key"
    ${PREFIX}create -hp 80000000 -rsa ${BITS[i]} -halg ${SHALG[i]} -si -kt f -kt p -opr signrsa${BITS[i]}priv.bin -opu signrsa${BITS[i]}pub.bin -opem signrsa${BITS[i]}pub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

    echo "Create an RSA ${BITS[i]} decryption key under the primary key"
    ${PREFIX}create -hp 80000000 -den -kt f -kt p -opr derrsa${BITS[i]}priv.bin -opu derrsa${BITS[i]}pub.bin -pwdp sto -pwdk dec > run.out
    checkSuccess $?

    echo "Create an RSA ${BITS[i]} ${SHALG[i]} restricted signing key under the primary key"
    ${PREFIX}create -hp 80000000 -rsa ${BITS[i]} -halg ${SHALG[i]} -sir -kt f -kt p -opr signrsa${BITS[i]}rpriv.bin -opu signrsa${BITS[i]}rpub.bin -opem signrsa${BITS[i]}rpub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

    echo "Create an RSA ${BITS[i]} ${SHALG[i]} not fixedTPM signing key under the primary key"
    ${PREFIX}create -hp 80000000 -rsa ${BITS[i]} -halg ${SHALG[i]} -sir -opr signrsa${BITS[i]}nfpriv.bin -opu signrsa${BITS[i]}nfpub.bin -opem signrsa${BITS[i]}nfpub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

done

SHALG=(sha256 sha384)
CURVE=(nistp256 nistp384)

for ((i = 0 ; i < 2 ; i++))
do

    echo "Create an ECC ${CURVE[i]} ${SHALG[i]} storage key under the primary key"
    ${PREFIX}create -hp 80000000 -ecc ${CURVE[i]} -halg ${SHALG[i]} -st -kt f -kt p -opr storeecc${CURVE[i]}priv.bin -opu storeecc${CURVE[i]}pub.bin -pwdp sto -pwdk sto > run.out
    checkSuccess $?

    echo "Create an ECC ${CURVE[i]} ${SHALG[i]} unrestricted signing key under the primary key"
    ${PREFIX}create -hp 80000000 -ecc ${CURVE[i]} -halg ${SHALG[i]} -si -kt f -kt p -opr signecc${CURVE[i]}priv.bin -opu signecc${CURVE[i]}pub.bin -opem signecc${CURVE[i]}pub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

    echo "Create an ECC ${CURVE[i]} ${SHALG[i]} restricted signing key under the primary key"
${PREFIX}create -hp 80000000 -ecc ${CURVE[i]} -halg ${SHALG[i]} -sir -kt f -kt p -opr signecc${CURVE[i]}rpriv.bin -opu signecc${CURVE[i]}rpub.bin -opem signecc${CURVE[i]}rpub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

    echo "Create an ECC ${CURVE[i]} ${SHALG[i]} not fixedTPM signing key under the primary key"
${PREFIX}create -hp 80000000 -ecc ${CURVE[i]} -halg ${SHALG[i]} -sir -opr signecc${CURVE[i]}nfpriv.bin -opu signecc${CURVE[i]}nfpub.bin -opem signecc${CURVE[i]}nfpub.pem -pwdp sto -pwdk sig > run.out
    checkSuccess $?

done

echo "Create a symmetric cipher key under the primary key"
${PREFIX}create -hp 80000000 -des -kt f -kt p -opr despriv.bin -opu despub.bin -pwdp sto -pwdk aes > run.out
RC=$?
checkWarning $RC "Symmetric cipher key may not support sign attribute"

if [ $RC -ne 0 ]; then
    echo "Create a rev 116 symmetric cipher key under the primary key"
    ${PREFIX}create -hp 80000000 -des -116 -kt f -kt p -opr despriv.bin -opu despub.bin -pwdp sto -pwdk aes > run.out
    checkSuccess $?
fi

for HALG in ${ITERATE_ALGS}

do

    echo "Create a ${HALG} unrestricted keyed hash key under the primary key"
    ${PREFIX}create -hp 80000000 -kh -kt f -kt p -opr khpriv${HALG}.bin -opu khpub${HALG}.bin -pwdp sto -pwdk khk -halg ${HALG} > run.out
    checkSuccess $?

    echo "Create a ${HALG} restricted keyed hash key under the primary key"
    ${PREFIX}create -hp 80000000 -khr -kt f -kt p -opr khrpriv${HALG}.bin -opu khrpub${HALG}.bin -pwdp sto -pwdk khk -halg ${HALG} > run.out
    checkSuccess $?



done

exit ${WARN}
