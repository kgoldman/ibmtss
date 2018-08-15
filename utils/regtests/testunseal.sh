#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testunseal.sh 1301 2018-08-15 21:46:19Z kgoldman $			#
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
echo "Seal and Unseal to Password"
echo ""

echo "Create a sealed data object"
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin > run.out
checkSuccess $?

echo "Load the sealed data object"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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
diff msg.bin tmp.bin > run.out
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
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Load the sealed data object under primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

# extend of aaa + 0 pad to digest length
# pcrreset -ha 16
# pcrextend -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ic aaa
# pcrread   -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
#
# 1d47f68aced515f7797371b554e32d47981aa0a0
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
# 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
# 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
#
# paste that with no white space to file policypcr16aaasha1.txt, etc.
#
# create AND term for policy PCR, PCR 16
# and then convert to binary policy

# > policymakerpcr -halg sha1   -bm 10000 -if policies/policypcr16aaasha1.txt   -v -pr -of policies/policypcr.txt
# 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
# convert to binary policy
# > policymaker -halg sha1   -if policies/policypcr.txt -of policies/policypcr16aaasha1.bin -pr -v
# 12 b6 dd 16 43 82 ca e4 5d 0e d0 7f 9e 51 d1 63 
# a4 24 f5 f2 

# > policymakerpcr -halg sha256 -bm 10000 -if policies/policypcr16aaasha256.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
# > policymaker -halg sha256 -if policies/policypcr.txt -of policies/policypcr16aaasha256.bin -pr -v
# 76 44 f6 11 ea 10 d7 60 da b9 36 c3 95 1e 1d 85 
# ec db 84 ce 9a 79 03 dd e1 c7 e0 a2 d9 09 a0 13 

# > policymakerpcr -halg sha384 -bm 10000 -if policies/policypcr16aaasha384.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
# > policymaker -halg sha384 -if policies/policypcr.txt -of policies/policypcr16aaasha384.bin -pr -v
# ea aa 8b 90 d2 69 b6 31 c0 85 91 e4 bf 29 a3 12 
# 87 04 f2 18 4c 02 ee 83 6a fb c4 c6 7f 28 c1 7f 
# 86 ea 22 b7 00 3d 06 fc b4 57 a3 b5 c4 f7 3c 95 

# > policymakerpcr -halg sha512 -bm 10000 -if policies/policypcr16aaasha512.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
# policymaker -halg sha512 -if policies/policypcr.txt -of policies/policypcr16aaasha512.bin -pr -v
# 1a 57 25 8d 99 64 d8 74 f0 85 0f 2c 8d 70 41 cc 
# be 21 c2 0f df 7e 07 e6 b1 99 ea 05 66 46 b7 fb 
# 23 55 77 4b 96 7e ab e2 65 db 5a 52 82 08 9c af 
# 3c c0 10 e4 99 36 5d ec 7f 0d 3e 6d 2a 62 6d 2e 

# sealed blob    80000001
# policy session 03000000

echo ""
echo "Seal and Unseal to PCRs"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr16aaa${HALG}.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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
    ${PREFIX}create -hp 80000000 -bl -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policyccduplicate.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object S1 at 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${ALG} storage key K1 80000002"
    ${PREFIX}load -hp 80000000 -ipr store${ALG}priv.bin -ipu store${ALG}pub.bin -pwdp sto > run.out
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
