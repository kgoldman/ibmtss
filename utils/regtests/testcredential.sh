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

# primary key 80000000
# storage key 80000001
# signing key 80000002
# policy session 03000000
# e5 87 c1 1a b5 0f 9d 87 30 f7 21 e3 fe a4 2b 46
# c0 45 5b 24 6f 96 ae e8 5d 18 eb 3b e6 4d 66 6a

echo ""
echo "Make and Activate Credential"
echo ""

echo "Use a random number as the credential input"
${PREFIX}getrandom -by 32 -of tmpcredin.bin > run.out
checkSuccess $?

echo "Load the storage key under the primary key, 80000001"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Create a restricted signing key under the primary key"
${PREFIX}create -hp 80000000 -sir -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk sig -pol policies/policyccactivate.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key, 80000002"
${PREFIX}load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Encrypt the credential using makecredential"
${PREFIX}makecredential -ha 80000001 -icred tmpcredin.bin -in h80000002.bin -ocred tmpcredenc.bin -os tmpsecret.bin > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code - activatecredential"
${PREFIX}policycommandcode -ha 03000000 -cc 00000147 > run.out
checkSuccess $?

echo "Activate credential"
${PREFIX}activatecredential -ha 80000002 -hk 80000001 -icred tmpcredenc.bin -is tmpsecret.bin -pwdk sto -ocred tmpcreddec.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Check the decrypted result"
diff tmpcredin.bin tmpcreddec.bin > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

# The low EK certificates remain in NV at the end of the test.  This
# makes the test, when run stand alone, useful for provisioning a TPM.
# It is not useful when the entire regression test runs, because a
# later test generates a new EPS (endorsement primary seed), which
# invalidates the EK and thus the certificate.

# optional NV index for Policy C
NVIDX=(01c07f01 01c07f02 01c07f03)
# corresponding hash algorithms
NVHALG=(sha256 sha384 sha512)
# NV index policy size includes hash algorithm
SIZ=(34 50 66)
# algorithms in binary from Algorithm Registry
HBIN=(000b 000c 000d)

# clear endorsement auth, may fail

${PREFIX}hierarchychangeauth -hi e -pwda eee > run.out
${PREFIX}dictionaryattacklockreset > run.out

# The mbedtls port does not support EC certificate creation yet */

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo ""
    echo "High Range Policy NV Index Provisioning"
    echo ""

# Policy Structure - See Section B.5 Policy NV Indexes Introduction Figure 1

# EK Policy is Policy B - a Policy OR of Policy A and Policy C
# Policy A is policy secret with endorsement auth
# Policy C is policyauthorizeNV
#	(for test, the policy in the NV index is policy secret with platform auth)

# Section B.6.2	Computing PolicyA - the standard IWG PolicySecret with endorsement auth
# policyiwgek.txt
# 000001514000000B
# (blank line for policyRef)
#
# policymaker -if policies/policyiwgek.txt -ns -halg sha256 -of policies/policyiwgeksha256.bin
# policymaker -if policies/policyiwgek.txt -ns -halg sha384 -of policies/policyiwgeksha384.bin
# policymaker -if policies/policyiwgek.txt -ns -halg sha512 -of policies/policyiwgeksha512.bin

# Section B.6.2 Computing PolicyA Table 13 PolicyA values - recalculated above

# 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
# 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
# 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee

# For test, put PolicySecret + platform auth in NV Index.  This is NOT the IWG standard, just for test.

# for prepending the hash algorithm identifier to make the TPMT_HA structure
# printf "%b" '\x00\x0b' > policies/sha256.bin
# printf "%b" '\x00\x0c' > policies/sha384.bin
# printf "%b" '\x00\x0d' > policies/sha512.bin

# policymaker -if policies/policysecretp.txt -halg sha256  -pr -of policies/policysecretpsha256.bin -pr
# policymaker -if policies/policysecretp.txt -halg sha384  -pr -of policies/policysecretpsha384.bin -pr
# policymaker -if policies/policysecretp.txt -halg sha512  -pr -of policies/policysecretpsha512.bin -pr

# prepend the algorithm identifiers - this test policy is written as
# the NV index data for PolicyC PolicyAuthorizeNV

# cat policies/sha256.bin policies/policysecretpsha256.bin >! policies/policysecretpsha256ha.bin
# cat policies/sha384.bin policies/policysecretpsha384.bin >! policies/policysecretpsha384ha.bin
# cat policies/sha512.bin policies/policysecretpsha512.bin >! policies/policysecretpsha512ha.bin

# NV Index Name Provisioning and Name verification against the specification

# Name from Section B.6.3 Computing Policy Index Names Table 14: Policy Index Names
NVNAME=(
    000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f
    000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c
    000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560
)

# interate through optional NV indexes
    for ((i = 0 ; i < 3; i++))
    do

	echo "Undefine optional NV index ${NVIDX[i]}"
	${PREFIX}nvundefinespace -ha ${NVIDX[i]} -hi o > run.out
	echo " INFO:"

	echo "Define optional ${NVHALG[i]} NV index ${NVIDX[i]} with PolicySecret for TPM_RH_ENDORSEMENT"
	${PREFIX}nvdefinespace -ha ${NVIDX[i]} -nalg ${NVHALG[i]} -hi o -pol policies/policyiwgek${NVHALG[i]}.bin -sz ${SIZ[i]} +at wa +at or +at ppr +at ar -at aw > run.out
	checkSuccess $?

	echo "Start a ${NVHALG[i]} policy session"
	${PREFIX}startauthsession -se p -halg ${NVHALG[i]} > run.out
	checkSuccess $?

	echo "Satisfy the policy, policysecret with endorsement auth"
	${PREFIX}policysecret -hs 03000000 -ha 4000000B > run.out
	checkSuccess $?

	echo "Get the session digest for debug"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Write the ${NVHALG[i]} ${NVIDX[i]} index to set the written bit before reading the Name"
	${PREFIX}nvwrite -ha ${NVIDX[i]} -if policies/policysecretp${NVHALG[i]}ha.bin  -se0 03000000 0 > run.out
	checkSuccess $?

	echo "Read the ${NVHALG[i]} Name"
	${PREFIX}nvreadpublic -ha ${NVIDX[i]} -ns > run.out
	checkSuccess $?

	echo "Verify the ${NVHALG[i]} Name"
	ACTUAL=`grep ${HBIN[i]} run.out |grep -v nvreadpublic`
	diff <(echo "${ACTUAL}" ) <(echo "${NVNAME[i]}" )
	checkSuccess $?

    done

# Section B.6.4	Computing PolicyC - TPM_CC_PolicyAuthorizeNV || nvIndex->Name)

# policyiwgekcsha256.txt
# 00000192000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f

# policyiwgekcsha384.txt
# 00000192000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c

# policyiwgekcsha512.txt
# 00000192000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560

# Section B.6.4 Computing PolicyC Table 15 PolicyC values - recalculated above

# policymaker -if policies/policyiwgekcsha256.txt -ns -halg sha256 -pr -of policies/policyiwgekcsha256.bin
# 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde

# policymaker -if policies/policyiwgekcsha384.txt -ns -halg sha384 -pr -of policies/policyiwgekcsha384.bin
# d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165

# policymaker -if policies/policyiwgekcsha512.txt -ns -halg sha512 -pr -of policies/policyiwgekcsha512.bin
# 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8


# Section B.6.5	Computing PolicyB - Policy OR of Policy A and Policy C

# policyiwgekbsha256.txt
# 00000171
# 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
# 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde
# policymaker -if policies/policyiwgekbsha256.txt -halg sha256 -pr -of policies/policyiwgekbsha256.bin
 # ca 3d 0a 99 a2 b9 39 06 f7 a3 34 24 14 ef cf b3
 # a3 85 d4 4c d1 fd 45 90 89 d1 9b 50 71 c0 b7 a0

# policyiwgekbsha384.txt
# 00000171
# 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
# d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165
# policymaker -if policies/policyiwgekbsha384.txt -halg sha384 -pr -of policies/policyiwgekbsha384.bin
 # b2 6e 7d 28 d1 1a 50 bc 53 d8 82 bc f5 fd 3a 1a
 # 07 41 48 bb 35 d3 b4 e4 cb 1c 0a d9 bd e4 19 ca
 # cb 47 ba 09 69 96 46 15 0f 9f c0 00 f3 f8 0e 12

# policyiwgekbsha512.txt
# 00000171
# 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee
# 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8
# policymaker -if policies/policyiwgekbsha512.txt -halg sha512 -pr -of policies/policyiwgekbsha512.bin
 # b8 22 1c a6 9e 85 50 a4 91 4d e3 fa a6 a1 8c 07
 # 2c c0 12 08 07 3a 92 8d 5d 66 d5 9e f7 9e 49 a4
 # 29 c4 1a 6b 26 95 71 d5 7e db 25 fb db 18 38 42
 # 56 08 b4 13 cd 61 6a 5f 6d b5 b6 07 1a f9 9b ea

# Section B.6.5	Computing PolicyB Table 16 - TPM_CC_PolicyOR || digests - recalculated above

    echo ""
    echo "High Range EK Certificate"
    echo ""

# Change endorsement and platform hierarchy passwords for testing

    echo "Change endorsement hierarchy password"
    ${PREFIX}hierarchychangeauth -hi e -pwdn eee > run.out
    checkSuccess $?

    echo "Change platform hierarchy password"
    ${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
    checkSuccess $?

# RSA EK certficates
    HALG=(sha256 sha384)
    CALG=("-rsa 2048" "-rsa 3072")
    CIDX=(01c00012 01c0001c)

# interate though high range RSA EK certficates
    for ((i = 0 ; i < 2 ; i++))
    do

	echo "Create an ${CALG[i]} EK certificate"
	${PREFIX}createekcert -high ${CALG[i]} -cakey cakey.pem -capwd rrrr -pwdp ppp -pwde eee -of tmp.der > run.out
	checkSuccess $?

	echo "Read the ${CALG[i]} EK certificate"
	${PREFIX}createek -high ${CALG[i]} -ce > run.out
	checkSuccess $?

	echo "CreatePrimary 80000001 and validate the ${CALG[i]} EK against the EK certificate"
	${PREFIX}createek -high -pwde eee -pwdk kkk ${CALG[i]} -cp -noflush > run.out
	checkSuccess $?

	echo "Validate the ${CALG[i]} EK certificate against the root"
	${PREFIX}createek -high ${CALG[i]} -root certificates/rootcerts.txt > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using the password"
	${PREFIX}create -hp 80000001 -si -pwdp kkk > run.out
	checkSuccess $?

	echo "Start a ${HALG[i]} policy session"
	${PREFIX}startauthsession -se p -halg ${HALG[i]} > run.out
	checkSuccess $?

	echo "Satisfy the policy A - policysecret with endorsement auth"
	${PREFIX}policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
	checkSuccess $?

	echo "Get the session digest for debug - 83 71 97 67, 8b bf 22 66, 1e 3b 76 50"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Policy OR ${HALG[i]}"
	${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - ca 3d 0a 99, b2 6e 7d 28, b8 22 1c a6"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using Policy A"
	${PREFIX}create -hp 80000001 -si -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Policy restart ${HALG[i]} 03000000"
	${PREFIX}policyrestart -ha 03000000 > run.out
	checkSuccess $?

	echo "Satisfy the policy in NV - policysecret with platform auth"
	${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - c8 b1 29 2e, b2 84 8c b4"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Satisfy Policy C - Policy Authorize NV"
	${PREFIX}policyauthorizenv -ha ${NVIDX[i]} -hs 03000000 > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - 37 67 e2 ed, d6 03 2c e6"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Policy OR ${HALG[i]}"
	${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - ca 3d 0a 99,  b2 6e 7d 28"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using Policy C"
	${PREFIX}create -hp 80000001 -si -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Flush the policy session ${HALG[i]} 03000000"
	${PREFIX}flushcontext -ha 03000000 > run.out
	checkSuccess $?

	echo "Flush the primary key ${CALG[i]} 80000001"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Undefine ${CALG[i]} NV index ${CIDX[i]}"
	${PREFIX}nvundefinespace -ha ${CIDX[i]} -hi p -pwdp ppp > run.out
	checkSuccess $?

    done

# ECC EK certficates
    HALG=(sha256 sha384)
    CALG=("-ecc nistp256" "-ecc nistp384")
    CIDX=(01c00014 01c00016)

# interate though high range ECC EK certficates.  Both the EK and
# certificate are removed in each iteration since the TPM resources
# are limited.

    for ((i = 0 ; i < 2 ; i++))
    do

	echo "Create an ${CALG[i]} EK certificate"
	${PREFIX}createekcert -high ${CALG[i]} -cakey cakeyecc.pem -capwd rrrr -caalg ec -pwdp ppp -pwde eee -of tmp.der > run.out
	checkSuccess $?

	echo "Read the ${CALG[i]} EK certificate"
	${PREFIX}createek -high ${CALG[i]} -ce > run.out
	checkSuccess $?

	echo "CreatePrimary 80000001 and validate the ${CALG[i]} EK against the EK certificate"
	${PREFIX}createek -high -pwde eee -pwdk kkk ${CALG[i]} -cp -noflush > run.out
	checkSuccess $?

	echo "Validate the ${CALG[i]} EK certificate against the root"
	${PREFIX}createek -high ${CALG[i]} -root certificates/rootcerts.txt > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using the password"
	${PREFIX}create -hp 80000001 -si -pwdp kkk > run.out
	checkSuccess $?

	echo "Start a ${HALG[i]} policy session"
	${PREFIX}startauthsession -se p -halg ${HALG[i]} > run.out
	checkSuccess $?

	echo "Satisfy the policy A - policysecret with endorsement auth"
	${PREFIX}policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
	checkSuccess $?

	echo "Get the session digest for debug - 83 71 97 67, 8b bf 22 66"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Policy OR ${HALG[i]}"
	${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - ca 3d 0a 99, b2 6e 7d 28"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using Policy A"
	${PREFIX}create -hp 80000001 -si -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Policy restart ${HALG[i]} 03000000"
	${PREFIX}policyrestart -ha 03000000 > run.out
	checkSuccess $?

	echo "Satisfy the policy in NV - policysecret with platform auth"
	${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - c8 b1 29 2e, b2 84 8c b4"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Satisfy Policy C - Policy Authorize NV"
	${PREFIX}policyauthorizenv -ha ${NVIDX[i]} -hs 03000000 > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - 37 67 e2 ed, d6 03 2c e6"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Policy OR ${HALG[i]}"
	${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
	checkSuccess $?

	echo "Get the ${HALG[i]} session digest for debug - ca 3d 0a 99,  b2 6e 7d 28"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Create a signing key under the ${CALG[i]} EK using Policy C"
	${PREFIX}create -hp 80000001 -si -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Flush the policy session ${HALG[i]} 03000000"
	${PREFIX}flushcontext -ha 03000000 > run.out
	checkSuccess $?

	echo "Flush the primary key ${CALG[i]} 80000001"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Undefine ${CALG[i]} NV index ${CIDX[i]}"
	${PREFIX}nvundefinespace -ha ${CIDX[i]} -hi p -pwdp ppp > run.out
	checkSuccess $?

    done

    echo ""
    echo "High Range Cleanup"
    echo ""

    echo "Reset endorsement hierarchy password"
    ${PREFIX}hierarchychangeauth -hi e -pwda eee > run.out
    checkSuccess $?

    echo "Reset platform hierarchy password"
    ${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
    checkSuccess $?

    for ((i = 0 ; i < 3; i++))
    do

	echo "Undefine optional ${HALG[i]} NV index ${NVIDX[i]}"
	${PREFIX}nvundefinespace -ha ${NVIDX[i]} -hi o > run.out
	checkSuccess $?

    done

    echo ""
    echo "Low Range EK Certificate"
    echo ""

# Policy Structure - See Section B.3 EK Templates in the Low Range

# EK Policy is Policy A is policy secret with endorsement auth

    echo "Set platform hierarchy auth"
    ${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
    checkSuccess $?

    echo "Change endorsement hierarchy password"
    ${PREFIX}hierarchychangeauth -hi e -pwdn eee > run.out
    checkSuccess $?

    for ALG in "-rsa 2048" "-ecc nistp256"
    do

	echo "Create an ${ALG} EK certificate"
	${PREFIX}createekcert ${ALG} -cakey cakey.pem -capwd rrrr -pwdp ppp -pwde eee -of tmp.der > run.out
	checkSuccess $?

	echo "Read the ${ALG} EK certificate"
	${PREFIX}createek ${ALG} -ce > run.out
	checkSuccess $?

	echo "Read the ${ALG} template - should fail"
	${PREFIX}createek ${ALG} -te > run.out
	checkFailure $?

	echo "Read the ${ALG} nonce - should fail"
	${PREFIX}createek ${ALG} -no > run.out
	checkFailure $?

	echo "CreatePrimary 80000001 and validate the ${ALG} EK against the EK certificate"
	${PREFIX}createek ${ALG} -pwde eee -cp -noflush > run.out
	checkSuccess $?

	echo "Validate the ${ALG} EK certificate against the root"
	${PREFIX}createek ${ALG} -root certificates/rootcerts.txt > run.out
	checkSuccess $?

	echo "Start a policy session"
	${PREFIX}startauthsession -se p > run.out
	checkSuccess $?

	echo "Satisfy the policy A - policysecret with endorsement auth"
	${PREFIX}policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
	checkSuccess $?

	echo "Get the session digest for debug - 83 71 97 67"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Create a signing key under the EK using Policy A"
	${PREFIX}create -hp 80000001 -si -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Flush the policy session 03000000"
	${PREFIX}flushcontext -ha 03000000 > run.out
	checkSuccess $?

	echo "Flush the primary key 80000001"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done

    echo "Clear platform hierarchy auth"
    ${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
    checkSuccess $?

    echo "Reset endorsement hierarchy password"
    ${PREFIX}hierarchychangeauth -hi e -pwda eee > run.out
    checkSuccess $?

fi

echo ""
echo "Low range EK certificates are now provisioned in NV"
echo ""

rm -f tmp.der
rm -r tmpcredin.bin
rm -f tmprpriv.bin 
rm -f tmprpub.bin
rm -f tmpcredenc.bin
rm -f tmpsecret.bin
rm -f tmpcreddec.bin


# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
