#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testrsa.sh 1209 2018-05-10 21:26:10Z kgoldman $			#
#										#
# (c) Copyright IBM Corporation 2015, 2017					#
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
${PREFIX}load -hp 80000000 -ipr derpriv.bin -ipu derpub.bin -pwdp pps > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin
checkSuccess $?

echo "Flush the decryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "RSA decryption key to sign with OID"
echo ""

echo "Load the RSA decryption key"
${PREFIX}load -hp 80000000 -ipu derpub.bin -ipr derpriv.bin -pwdp pps > run.out
checkSuccess $?

HALG=("sha1" "sha256" "sha384")
HSIZ=("20" "32" "48")

for ((i = 0 ; i < 3 ; i++))
do

    echo "Decrypt/Sign with a caller specified OID - ${HALG[i]}"
    ${PREFIX}rsadecrypt -hk 80000001 -pwdk dec -ie policies/${HALG[i]}aaa.bin -od tmpsig.bin -oid ${HALG[i]} > run.out
    checkSuccess $?

    echo "Encrypt/Verify - ${HALG[i]}"
    ${PREFIX}rsaencrypt -hk 80000001 -id tmpsig.bin -oe tmpmsg.bin > run.out
    checkSuccess $?

    echo "Verify Result - ${HALG[i]} ${HSIZ[i]} bytes"
    tail -c ${HSIZ[i]} tmpmsg.bin > tmpdig.bin
    diff tmpdig.bin policies/${HALG[i]}aaa.bin
    checkSuccess $?

done

echo "Flush the RSA signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -f tmpmsg.bin
rm -f tmpdig.bin
rm -f tmpsig.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

# ${PREFIX}flushcontext -ha 80000001
