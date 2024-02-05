#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2024					#
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

# used for the name in policy authorize

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi

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
${PREFIX}create -hp 80000000 -bl -kt f -kt p -uwa -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
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
echo "Seal and Unseal to PCR 16"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -uwa -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr16aaa${HALG}.bin > run.out
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

# This test uses the same values for PCR 16 and PCR 23 for simplicity.
# For different values, calculate the PCR white list value and change
# the cat line to use two different values.

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
# create AND term for policy PCR, PCR 16 and 23
# and then convert to binary policy

# > cat policies/policypcr16aaasha1.txt policies/policypcr16aaasha1.txt >! policypcra.txt
# > policymakerpcr -halg sha1   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
#0000017f0000000100040300008173820c1f0f279933a5a58629fe44d081e740d4ae
# > policymaker -halg sha1   -if policypcr.txt -of policies/policypcr1623aaasha1.bin -pr -v
 # policy digest length 20
 # b4 ed de a3 35 87 d7 43 29 f6 a8 d1 e7 89 92 64 
 # 46 f0 4c 85 

# > cat policies/policypcr16aaasha256.txt policies/policypcr16aaasha256.txt >! policypcra.txt
# > policymakerpcr -halg sha256   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000b030000815a9f104273886b7ec8919a449d440d107d0da5df367e28c6ac145c9023cb5e76
# > policymaker -halg sha256   -if policypcr.txt -of policies/policypcr1623aaasha256.bin -pr -v
 # policy digest length 32
 # 84 ff 2f f1 2d 37 cb 23 fb 3d 14 d9 66 77 ca ec 
 # 48 94 5c 0b 83 e5 ea a2 be 98 e9 75 aa 21 e3 d6 

# > cat policies/policypcr16aaasha384.txt policies/policypcr16aaasha384.txt >! policypcra.txt
# > policymakerpcr -halg sha384   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000c0300008105f7f12c86c3b0ed988d369a96d401bb4a58b74f982eb03e8474cb66076114ba2b933dd95cde1c7ea69d0a797abc99d4
# > policymaker -halg sha384   -if policypcr.txt -of policies/policypcr1623aaasha384.bin -pr -v
 # policy digest length 48
 # 4b 03 cd b3 eb 07 15 14 7c 49 93 43 a5 65 ee dc 
 # 86 22 7c 86 36 20 97 a2 5e 0f 34 2e d2 4f 7e ad 
 # a0 61 8b 5e d7 ba bb e3 5e f0 ab ea 99 55 df 84 

# > cat policies/policypcr16aaasha512.txt policies/policypcr16aaasha512.txt >! policypcra.txt
# > policymakerpcr -halg sha512   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000d03000081266ae24c92f63b30322e9c22e44e9540313a2223ae79b27eafe798168bef373ac55de22a0ca78ec8b2e9402aa1f8b47b6ef40e9e53aebaa694af58f240efa0fd
# > policymaker -halg sha512   -if policypcr.txt -of policies/policypcr1623aaasha512.bin -pr -v
 # policy digest length 64
 # 13 84 59 76 b8 d4 d8 a9 a4 7d 75 0e 3e 81 cd c2 
 # 78 08 ec 95 d7 13 e8 ef 0c 0b 85 c7 38 2e ad 46 
 # e4 72 31 1d 11 a3 38 17 54 e5 cf 2e 6d 23 67 6d 
 # 39 5a 93 51 9d f3 f0 90 56 4d 66 f8 7b 90 fc 61 

# sealed blob    80000001
# policy session 03000000

echo ""
echo "Seal and Unseal to PCR 16 and 23"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -uwa -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr1623aaa${HALG}.bin > run.out
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

    echo "PCR 23 Reset"
    ${PREFIX}pcrreset -ha 23 > run.out
    checkSuccess $?

    echo "Extend PCR 16 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 16 -if policies/aaa > run.out
    checkSuccess $?

    echo "Extend PCR 23 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 23 -if policies/aaa > run.out
    checkSuccess $?

    echo "Policy PCR, update with the correct PCR 16 and 23 values"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 810000 > run.out
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

#
# Sample application to demonstrate the policy authorize solution to
# the PCR brittleness problem when sealing.  Rather than sealing
# directly to the PCRs, the blob is sealed to an authorizing public
# key.  The authorizing private key signs the approved policy PCR
# digest.
#
# Name for 80000001 authorizing key (output of loadexternal below) is
# used to calculate the policy authorize policy
#
# 00044234c24fc1b9de6693a62453417d2734d7538f6f
# 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# 000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
# 000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
#
# Use 0000016a || the above Name, with a following blank line for
# policyRef to make policies/policyauthorizesha[].txt. Use policymaker
# to create the binary policy.  This will be the session digest after
# the policyauthorize command.
#
# > policymaker -halg sha[] -if policies/policyauthorizesha[].txt -of policies/policyauthorizesha[].bin -pr
# 16 82 10 58 c0 32 8c c4 e5 2e c4 ec ce 61 6c 0a 
# f4 8a 30 88 
#
# eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
# ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
#
# 5c c6 34 89 fe f9 c8 42 7e fe 2c 5f 08 39 74 b6 
# d9 a8 36 02 4a cd d9 70 7e f0 b9 fd 15 26 56 da 
# a5 07 0a 9b bf d6 66 df 49 d2 5b 8d 50 8e 16 38 
#
# c9 c8 29 fb bc 75 54 99 db 48 b7 26 88 24 d1 f8 
# 29 72 01 60 6b d6 5f 41 8e 06 98 7e f7 3e 6a 7e 
# 25 82 c7 6d 8f 1c 36 43 68 01 ee 56 51 d5 06 b4 
# 68 4c fe d1 d0 6a d7 65 23 3f c2 92 94 fd 2c c5 

# setup and policy PCR calculations
#
# 16 is the debug PCR, a typical application may seal to PCR 0-7
# > pcrreset -ha 16
#
# policies/aaa represents the new 'BIOS' measurement hash extended
# into all PCR banks
#
# > pcrextend -ha 16 -halg [] -if policies/aaa
#
# These are the new PCR values to be authorized.  Typically, these are
# calculated by other software based on the enterprise.  Here, they're
# just read from the TPM.
#
# > pcrread -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
#
# 1d47f68aced515f7797371b554e32d47981aa0a0
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
# 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
# 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
#
# Put the above authorized PCR value in an intermediate file
# policies/policypcr16aaasha1.txt for policymakerpcr, and create the
# policypcr AND term policies/policypcr.txt.  policymakerpcr prepends the command code and
# PCR select bit mask.
#
# > policymakerpcr -halg sha[] -bm 010000 -if policies/policypcr16aaasha1.txt -of policies/policypcr.txt -pr -v
#
# 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
# 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
# 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
# 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
#
# Send the policymakerpcr AND term result to policymaker to create the
# Policy PCR digest.  This is the authorized policy signed by the
# authorizing private key.
#
# > policymaker -halg sha[] -if policies/policypcr.txt -of policies/policypcr16aaasha[].bin -v -pr -ns
#
# 12b6dd164382cae45d0ed07f9e51d163a424f5f2
# 7644f611ea10d760dab936c3951e1d85ecdb84ce9a7903dde1c7e0a2d909a013
# eaaa8b90d269b631c08591e4bf29a3128704f2184c02ee836afbc4c67f28c17f86ea22b7003d06fcb457a3b5c4f73c95
# 1a57258d9964d874f0850f2c8d7041ccbe21c20fdf7e07e6b199ea056646b7fb2355774b967eabe265db5a5282089caf3cc010e499365dec7f0d3e6d2a626d2e

echo ""
echo "Policy PCR with Policy Authorize (PCR brittleness solution)"
echo ""

for HALG in ${ITERATE_ALGS}
do
    # One time task, create sealed blob with policy of policyauthorize
    # with Name of authorizing key

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -uwa -opr tmppriv.bin -opu tmppub.bin -pwdp sto -if msg.bin -pol policies/policyauthorize${HALG}.bin > run.out
    checkSuccess $?

    # Once per new PCR approved values, authorizing PCRs in policy${HALG}.bin

    echo "Openssl generate and sign aHash (empty policyRef) ${HALG}"
    openssl dgst -${HALG} -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policypcr16aaa${HALG}.bin > run.out 2>&1

    # Once per boot, simulating setting PCRs to authorized values

    echo "Reset PCR 16 back to zero"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR extend PCR 16 ${HALG}"
    ${PREFIX}pcrextend -ha 16 -halg ${HALG} -if policies/aaa > run.out
    checkSuccess $?

    # beginning of unseal process, policy PCR

    echo "Start a policy session ${HALG}"
    ${PREFIX}startauthsession -halg ${HALG} -se p > run.out
    checkSuccess $?

    echo "Policy PCR, update with the correct digest ${HALG}"
    ${PREFIX}policypcr -ha 03000000 -halg ${HALG} -bm 10000 > run.out
    checkSuccess $?

    echo "Policy get digest, should be policies/policypcr16aaa${HALG}.bin"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    # policyauthorize process

    echo "Load external just the public part of PEM authorizing key ${HALG} 80000001"
    ${PREFIX}loadexternal -hi p -halg ${HALG} -nalg ${HALG} -ipem policies/rsapubkey.pem -ns > run.out
    checkSuccess $?

    echo "Verify the signature to generate ticket 80000001 ${HALG}"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if policies/policypcr16aaa${HALG}.bin -is pssig.bin -raw -tk tkt.bin > run.out
    checkSuccess $?

    echo "Policy authorize using the ticket"
    ${PREFIX}policyauthorize -ha 03000000 -appr policies/policypcr16aaa${HALG}.bin -skn ${TPM_DATA_DIR}/h80000001.bin -tk tkt.bin > run.out
    checkSuccess $?

    echo "Get policy digest, should be policies/policyauthorize${HALG}.bin"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Flush the verification public key 80000001"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    # load the sealed blob and unseal

    echo "Load the sealed data object 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Unseal the data blob using a password session, userWithAuth CLEAR, should fail"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin > run.out
    checkFailure $?

    echo "Unseal the data blob using the policy session"
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

for ALG in "rsa2048" "eccnistp256" "eccnistp384"
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

echo ""
echo "Pre-OS Trusted Path demo"
echo ""

#
# A trusted path beween a CPU and the TPM portects the seal and unseal
# of a 'sealed secret'.  An encrypted sessions prevent a MiM attack.
# The CPU secret is applied to an NV extend Index.  The run time unseal
# is authorized as long as the CPU secret extend occurred, which
# prevents the TPM from being moved to another platform.

# It leverages the EK and its certificate to create a trusted path.
# The CPU secret is used twice, first in a bind encrypt session when
# extending the secret to NV, and next as the data extended into an NV
# or derived secrets.
#

# Temporary files

# tmpext.bin - extend of CPU secret
# tmpuspol.bin - Unseal data policy
# tmpseal.txt - test sealed data in plaintext
# tmppub.bin - sealed data public part
# tmppriv.bin - sealed data private part
# tmpunseal.txt - unsealed data in plaintext

# Key Slots

# 80000000 EK
# 80000001 SRK
# 80000002 Sealed Data

# Notation

# DEMO: Actions that are just for the demo script, not for the actual application
# PROVISION: Actions taken once during provisioning
# RUNTIME: Actions taken at runtime

# Policies

# NV Extend Index
#
# Policy OR of
# Policy A - command code NV read (only for debug)
# Policy B - command code NV extend
# Policy C - command code Policy NV (for the unseal)

# Sealed Data
#
# Policy command code unseal
# AND
# policynv equals the CPU secret extended into the NV Index

# If this changes, the unseal policynv calculation must also change
CPU_SECRET=cpusecret

# test sealed secret
echo "sealedsecret" > tmpseal.txt

# clean up from previous failed run
${PREFIX}nvundefinespace -ha 01000000 -hi p > run.out

echo "DEMO: Context save the regression test SRK to free up a key slot"
${PREFIX}contextsave -ha 80000000 -of tmpsrk.bin > run.out
checkSuccess $?

echo "DEMO: Flush the regression test SRK"
${PREFIX}flushcontext -ha 80000000 > run.out
checkSuccess $?

# mbedtls port doesn't support X.509 certificate validation generation

if   [ ${CRYPTOLIBRARY} == "openssl" ]; then
echo "DEMO: Create EK certificate for SW TPM"
${PREFIX}createekcert -rsa 2048 -cakey cakey.pem    -capwd rrrr > run.out
checkSuccess $?
fi

#
# Provision the NV Extend Index
#

# The NV index policy permits unauthorized read OR extend

# Policy A - command code NV read
# tmp.txt:
# 0000016c0000014e
# > policymaker -if policies/policyccnvread.txt -ns -v -of policies/policyccnvread.bin
# 47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f

# Policy B - command code NV extend
# 0000016c00000136
# > policymaker -if policies/policyccnvextend.txt -ns -v -of policies/policyccnvextend.bin
# b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7

# Policy C - command code Policy NV
# 0000016c00000149
# > policymaker -if policies/policyccpolicynv.txt -ns -v -of policies/policyccpolicynv.bin
# 203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43

# policyor
# policyornvrep.txt:  policy OR command code | Policy A | Policy B | Policy C
# 0000017147ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92fb6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43
# > policymaker -if policies/policyornvrep.txt -ns -v -of policies/policyornvrep.bin
# 7f17937e206279a3f755fb60f40cf126b70e5b1d9bf202866d527613874a64ac

echo ""
echo "Provision NV Index and Create Sealed Blob"
echo ""

# createek also validates the EK public key against the EK certificate and
# walks the certificate chain.  It leaves the EK loaded at 80000000

# mbedtls port doesn't support X.509 certificate validation

echo "PROVISION: Create the EK for the salted session 80000000"
if   [ ${CRYPTOLIBRARY} == "openssl" ]; then
${PREFIX}createek -rsa 2048 -cp -noflush -root certificates/rootcerts.txt > run.out
elif [ ${CRYPTOLIBRARY} == "mbedtls" ]; then
${PREFIX}createek -rsa 2048 -cp -noflush -nopub > run.out
fi
checkSuccess $?


echo "PROVISION: Start the EK salted session 02000000 for for an authenticated channel"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

# the salted session HMAC ensures thet the storge key Name is authentic

echo "PROVISION: Create the primary parent for the unseal data 80000001"
${PREFIX}createprimary -hi p -pwdk sto -se0 02000000 21 > run.out
checkSuccess $?

# the salted session encrypts the NV index password, the CPU secret,
# and ensures that the NV index Name us authentic

echo "PROVISION: Define the NV Index, use an encrypt session to encrypt the password"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn ${CPU_SECRET} -ty e +at ody +at stc -pol policies/policyornvrep.bin -se0 02000000 21 > run.out
checkSuccess $?

# Do this to calculate the NV Index Name for the policy

# echo "DEMO: NV Extend to set the written bit, needed for the NV Index Name"
# ${PREFIX}nvextend -ha 01000000 -ic 0 -pwdn ${CPU_SECRET} > run.out
# checkSuccess $?

# echo "DEMO: Read the NV Index Name"
# ${PREFIX}nvreadpublic -ha 01000000 -ns > run.out
# checkSuccess $?

# NV Index Name 000bbc2784f51dda6d27b92784068c6b8c7c94a4cc530b434e16ef95222fe68e6c92

# Calculate the hash of the CPU secret for the unseal.  Use
# policymaker to calculate the eventual NV extend result in software.

# 'cpusecret' in hexascii
echo -n 637075736563726574 > tmp.txt

# 637075736563726574
${PREFIX}policymaker -if tmp.txt -ns -of tmpext.bin > run.out
# policy digest:
# 0ad80f8e4450587760d9137df41c9374f657bafa621fe37d4d5c8cecf0bcce5e

# Calculate the sealed object policy
# Policy command code unseal AND policynv equals

# AND term 1 command code unseal

# 0000016c0000015e

# AND term 2 policynv

# args = Hash of operandB.buffer || offset || operation)

# tmp.txt is operandB.buffer input in hexascii, offset 0, operand 0 means equals
# 0ad80f8e4450587760d9137df41c9374f657bafa621fe37d4d5c8cecf0bcce5e00000000

# Use policymaker with -nz to do a hash of hexascii
# > policymaker -nz -if tmp.txt -v -ns 
# args is a hash of the above input: 
# 19936a82d9b3fabcc3794b1b9c1dbb71a7de7f6e360cb01f6a6f082f7e66dc60

# CC_PolicyNV || args || Name
# 0000014919936a82d9b3fabcc3794b1b9c1dbb71a7de7f6e360cb01f6a6f082f7e66dc60000bbc2784f51dda6d27b92784068c6b8c7c94a4cc530b434e16ef95222fe68e6c92

# Combine the two AND terms to calculate the policy
# tmp.txt
# 0000016c0000015e
# 0000014919936a82d9b3fabcc3794b1b9c1dbb71a7de7f6e360cb01f6a6f082f7e66dc60000bbc2784f51dda6d27b92784068c6b8c7c94a4cc530b434e16ef95222fe68e6c92

echo 0000016c0000015e > tmp.txt
echo 0000014919936a82d9b3fabcc3794b1b9c1dbb71a7de7f6e360cb01f6a6f082f7e66dc60000bbc2784f51dda6d27b92784068c6b8c7c94a4cc530b434e16ef95222fe68e6c92 >> tmp.txt

${PREFIX}policymaker -if tmp.txt -ns -v -of tmpuspol.bin > run.out
#  intermediate policy digest length 32
#  e6 13 13 70 76 52 4b de 48 75 33 86 58 84 e9 73 
#  2e be e3 aa cb 09 5d 94 a6 de 49 2e c0 6c 46 fa 
#  intermediate policy digest length 32
#  b2 f6 13 21 27 36 b6 f1 c2 84 07 a3 fb a2 7e 14 
#  c1 84 c8 21 34 3a 8c 3b fe 23 cd 5f 2e 76 d0 51 
# policy digest:
# b2f613212736b6f1c28407a3fba27e14c184c821343a8c3bfe23cd5f2e76d051

echo "PROVISION: Create the sealed data object under the primary storage key 80000001, encrypt session"
${PREFIX}create -hp 80000001 -pwdp sto -bl -if tmpseal.txt -kt f -kt p -pol tmpuspol.bin -uwa -opu tmppub.bin -opr tmppriv.bin -se0 02000000 20 
checkSuccess $?

echo ""
echo "Run time - Extend the CPU secret unto the NV Index"
echo ""

#
# Run time - Extend the CPU secret unto the NV Index
#

# Real code would read the NV Index Name at reboot and validate the
# value to ensure that the NV Index has not been undefined and then
# defined differently.

echo "RUNTIME: Read the NV Index Name"
${PREFIX}nvreadpublic -ha 01000000 -ns > run.out
checkSuccess $?

echo "RUNTIME: Start policy session 03000000 for NV authorization, bind to CPU secret for parameter encryption"
${PREFIX}startauthsession -se p -bi 01000000 -pwdb ${CPU_SECRET} > run.out
checkSuccess $?

echo "RUNTIME: Policy command code NV extend"
${PREFIX}policycommandcode -ha 03000000 -cc 00000136 > run.out
checkSuccess $?

echo "DEMO: Should be policy B first intermediate value b6a2 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "RUNTIME: Policy OR the NV Policies A, B, C"
${PREFIX}policyor -ha 03000000 -if policies/policyccnvread.bin -if policies/policyccnvextend.bin -if policies/policyccpolicynv.bin > run.out
checkSuccess $?

echo "DEMO: Should be policy OR 7f17 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "RUNTIME: Extend the CPU secret into the NV Index, use parameter encryption"
${PREFIX}nvextend -ha 01000000 -ic ${CPU_SECRET} -se0 03000000 21 > run.out
checkSuccess $?

echo "DEMO: Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "DEMO: Policy command code NV read"
${PREFIX}policycommandcode -ha 03000000 -cc 0000014e > run.out
checkSuccess $?

echo "DEMO: Policy OR"
${PREFIX}policyor -ha 03000000 -if policies/policyccnvread.bin -if policies/policyccnvextend.bin -if policies/policyccpolicynv.bin > run.out
checkSuccess $?

echo "DEMO: Read NV Index, should be extend of CPU secret 0ad8 ..."
${PREFIX}nvread -ha 01000000 -se0 03000000 0 > run.out
checkSuccess $?

echo ""
echo "Run time - Unseal"
echo ""

# The application would recreate the EK at 80000000 and the primary
# parent for the unseal data at 80000001

echo "RUNTIME: Load the sealed data 80000002 under the storage parent 80000001"
${PREFIX}load -hp 80000001 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
checkSuccess $?

echo "RUNTIME: Start a PolicyNV authorization policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "RUNTIME: Policy command code PolicyNV"
${PREFIX}policycommandcode -ha 03000000 -cc 00000149 > run.out
checkSuccess $?

echo "RUNTIME: Policy OR the NV Policies A, B, C"
${PREFIX}policyor -ha 03000000 -if policies/policyccnvread.bin -if policies/policyccnvextend.bin -if policies/policyccpolicynv.bin > run.out
checkSuccess $?

echo "RUNTIME: Start a unseal policy session 03000001, salt for for response parameter encryption"
${PREFIX}startauthsession -se p -hs 80000000 > run.out
checkSuccess $?

echo "RUNTIME: Policy command code Unseal"
${PREFIX}policycommandcode -ha 03000001 -cc 0000015e > run.out
checkSuccess $?

echo "DEMO: Should be policy Unseal first intermediate value e6 13 13 70 ..."
${PREFIX}policygetdigest -ha 03000001 > run.out
checkSuccess $?

echo "RUNTIME: Policy NV, operation equals extend of CPU secret"
${PREFIX}policynv -ha 01000000 -hs 03000001 -op 0 -if tmpext.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "DEMO: Should be policy Unseal second intermediate value b2 f6 13 21 ..."
${PREFIX}policygetdigest -ha 03000001 > run.out
checkSuccess $?

echo "RUNTIME: Unseal, use the salt encrypt session"
${PREFIX}unseal -ha 80000002 -of tmpunseal.txt -se0 03000001 40 > run.out
checkSuccess $?

echo "DEMO: Verify the unseal result"
diff tmpseal.txt tmpunseal.txt > run.out
checkSuccess $?

# cleanup

echo "DEMO: Undefine the NV Index"
${PREFIX}nvundefinespace -ha 01000000 -hi p > run.out
checkSuccess $?

echo "DEMO: Flush EK at 80000000"
${PREFIX}flushcontext -ha 80000000 > run.out
checkSuccess $?

echo "DEMO: Flush primary storage key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "DEMO: Flush sealed data at 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Context load the regression test SRK at 80000000"
${PREFIX}contextload -if tmpsrk.bin > run.out
checkSuccess $?

# cleanup

rm -f tmpseal.txt
rm -f tmpunseal.txt
rm -f tmppriv.bin
rm -f tmppub.bin
rm -f tmp.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmppriv1.bin
rm -f pssig.bin
rm -f tkt.bin
rm -f tmp.txt
rm -f tmpext.bin
rm -f tmpsrk.bin
rm -f tmpuspol.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
