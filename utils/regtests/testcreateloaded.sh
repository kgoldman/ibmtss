#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testcreateloaded.sh 913 2017-01-16 21:41:07Z kgoldman $		#
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
echo "CreateLoaded"
echo ""

echo ""
echo "CreateLoaded Primary Key"
echo ""

for HIER in "40000001" "4000000c" "4000000b"
do

    echo "CreateLoaded primary key, parent ${HIER}"
    ${PREFIX}createloaded -hp ${HIER} -st -kt f -kt p -pwdk ppp > run.out
    checkSuccess $?

    echo "Create a storage key under the primary key"
    ${PREFIX}create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the primary storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key - should fail"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkFailure $?

    echo "CreateLoaded recreate owner primary key"
    ${PREFIX}createloaded -hp ${HIER} -st -kt f -kt p -pwdk ppp > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the primary storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "CreateLoaded Child Key"
echo ""

echo "CreateLoaded child key, parent 80000000"
${PREFIX}createloaded -hp 80000000 -st -kt f -kt p -pwdp pps -pwdk ppp > run.out
checkSuccess $?

echo "Create a signing key under the child key"
${PREFIX}create -hp 80000001 -si -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
checkSuccess $?

echo "Load the signing key under the child key"
${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the child key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "CreateLoaded Derived Key"
echo ""

echo "Create a derivation parent under the primary key"
${PREFIX}create -hp 80000000 -dp -opr tmpdppriv.bin -opu tmpdppub.bin -pwdp pps -pwdk dp > run.out
checkSuccess $?

echo "Load the derivation parent to 80000001"
${PREFIX}load -hp 80000000 -ipr tmpdppriv.bin -ipu tmpdppub.bin -pwdp pps > run.out
checkSuccess $?

echo "Create a signing key under the derivation parent key"
${PREFIX}createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp dp -ecc nistp256 > run.out
checkSuccess $?

echo "Flush the derivation parent"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

rm -f tmpdppriv.bin
rm -f tmpdppub.bin
