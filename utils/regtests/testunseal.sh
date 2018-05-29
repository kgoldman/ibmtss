#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testunseal.sh 1214 2018-05-14 20:44:25Z kgoldman $			#
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
echo "Seal and Unseal to Password"
echo ""

echo "Create a sealed data object"
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin > run.out
checkSuccess $?

echo "Load the sealed data object"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
checkSuccess $?

echo "Unseal the data blob"
${PREFIX}unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Unseal with bad password - should fail"
${PREFIX}unseal -ha 80000001 -pwd xxx > run.out
checkFailure $?

echo "Flush the sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Create a primary sealed data object"
${PREFIX}createprimary -bl -kt f -kt p -pwdk seap -if msg.bin > run.out
checkSuccess $?

echo "Unseal the primary data blob"
${PREFIX}unseal -ha 80000001 -pwd seap -of tmp.bin > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin
checkSuccess $?

echo "Flush the primary sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Seal and Unseal to PolicySecret Platform Auth"
echo ""

# policy is policy secret pointing to platform auth
# 000001514000000C plus newline for policyRef

echo "Change platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Create a sealed data object with policysecret platform auth under primary key"
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Load the sealed data object under primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Unseal the data blob - policy failure, policysecret not run"
${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy Secret with PWAP session and platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
checkSuccess $?

echo "Unseal the data blob"
${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Change platform hierarchy auth back to null"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Flush the sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# SHA-1

# extend of aaa + 0 pad to digest length
# 1d 47 f6 8a ce d5 15 f7 79 73 71 b5 54 e3 2d 47 
# 98 1a a0 a0 

# paste that with no white space to file policypcr16aaasha1.txt

# create AND term for policy PCR, PCR 16
# > policymakerpcr -halg sha1 -bm 10000 -if policies/policypcr16aaasha1.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d

# convert to binary policy
# > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcr16aaasha1.bin -pr -v
# 12 b6 dd 16 43 82 ca e4 5d 0e d0 7f 9e 51 d1 63 
# a4 24 f5 f2 

# SHA-256

# extend of aaa + 0 pad to digest length
# > pcrextend -ha 16 -if policies/aaa

# read the PCR 16 value back
# > pcrread -ha 16 -ns
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb

# paste that with no white space to file policypcr16aaasha256.txt

# create AND term for policy PCR, PCR 16
# > policymakerpcr -bm 10000 -if policies/policypcr16aaasha256.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13

# convert to binary policy
# > policymaker -if policies/policypcr.txt -of policies/policypcr16aaasha256.bin -pr -v
# 76 44 f6 11 ea 10 d7 60 da b9 36 c3 95 1e 1d 85 
# ec db 84 ce 9a 79 03 dd e1 c7 e0 a2 d9 09 a0 13 

# sealed blob    80000001
# policy session 03000000

echo ""
echo "Seal and Unseal to PCRs"
echo ""

for HALG in "sha1" "sha256"
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policypcr16aaa${HALG}.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    checkSuccess $?

    echo "Start a policy session ${HALG}"
    ${PREFIX}startauthsession -se p -halg ${HALG} > run.out
    checkSuccess $?

    echo "PCR 16 Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "Unseal the data blob - policy failure, policypcr not run"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    checkFailure $?

    echo "Policy PCR, update with the wrong PCR 16 value"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 10000 > run.out
    checkSuccess $?

    echo "Unseal the data blob - policy failure, PCR 16 incorrect"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    checkFailure $?

    echo "Extend PCR 16 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 16 -if policies/aaa > run.out
    checkSuccess $?

    echo "Policy restart, set back to zero"
    ${PREFIX}policyrestart -ha 03000000 > run.out 
    checkSuccess $?

    echo "Policy PCR, update with the correct PCR 16 value"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 10000 > run.out
    checkSuccess $?

    echo "Unseal the data blob"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    checkSuccess $?

    echo "Flush the sealed object"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the policy session"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?

done

echo ""
echo "Import and Unseal"
echo ""

# primary key P1 80000000
# sealed data S1 80000001 originally under 80000000
# target storage key K1 80000002

for ALG in "" "ecc"
do 

    echo "Create a sealed data object S1 under the primary key P1 80000000"
    ${PREFIX}create -hp 80000000 -bl -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policyccduplicate.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object S1 at 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    checkSuccess $?

    echo "Load the ${ALG} storage key K1 80000002"
    ${PREFIX}load -hp 80000000 -ipr store${ALG}priv.bin -ipu store${ALG}pub.bin -pwdp pps > run.out
    checkSuccess $?

    echo "Start a policy session 03000000"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Policy command code, duplicate"
    ${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
    checkSuccess $?

    echo "Get policy digest"
    ${PREFIX}policygetdigest -ha 03000000 > run.out 
    checkSuccess $?

    echo "Duplicate sealed data object S1 80000001 under ${ALG} K1 80000002"
    ${PREFIX}duplicate -ho 80000001 -pwdo sig -hp 80000002 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Flush the original S1 to free object slot for import"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Import S1 under ${ALG} K1 80000002"
    ${PREFIX}import -hp 80000002 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv1.bin > run.out
    checkSuccess $?

    echo "Load the duplicated sealed data object S1 at 80000001 under ${ALG} K1 80000002"
    ${PREFIX}load -hp 80000002 -ipr tmppriv1.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Unseal the data blob"
    ${PREFIX}unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
    checkSuccess $?

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    checkSuccess $?

    echo "Flush the sealed data object at 80000001"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the storage key at 80000002"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the session"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?

done

rm -r tmppriv.bin
rm -r tmppub.bin
rm -r tmp.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmppriv1.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
