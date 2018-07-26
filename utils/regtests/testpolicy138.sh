#!/bin/bash

#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testpolicy138.sh 1277 2018-07-23 20:30:23Z kgoldman $	#
#										#
# (c) Copyright IBM Corporation 2016 - 2018					#
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

# Policy command code - sign

# cc69 18b2 2627 3b08 f5bd 406d 7f10 cf16
# 0f0a 7d13 dfd8 3b77 70cc bcd1 aa80 d811

# NV index name after written

# 000b 
# 5e8e bdf0 4581 9419 070c 7d57 77bf eb61 
# ffac 4996 ea4b 6fba de6d a42b 632d 4918   

# Policy Authorize NV with above Name
                              
# 66 1f a1 02 db cd c2 f6 a0 61 7b 33 a0 ee 6d 95 
# ab f6 2c 76 b4 98 b2 91 10 0d 30 91 19 f4 11 fa 

# Policy in NV index 01000000
# signing key 80000001 

echo ""
echo "Policy Authorize NV"
echo ""

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Create a signing key, policyauthnv"
${PREFIX}create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizenv.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "NV Define Space"
${PREFIX}nvdefinespace -hi o -ha 01000000 -sz 50 > run.out
checkSuccess $?
    
echo "NV not written, policyauthorizenv - should fail"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkFailure $?

echo "Write algorithm ID into NV index 01000000"
${PREFIX}nvwrite -ha 01000000 -off 0 -if policies/sha256.bin > run.out
checkSuccess $?

echo "Write policy command code sign into NV index 01000000"
${PREFIX}nvwrite -ha 01000000 -off 2 -if policies/policyccsign.bin > run.out
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy get digest - should be cc 69 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkSuccess $?

echo "Policy get digest - should be 66 1f ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy and wrong password"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
checkSuccess $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkSuccess $?

echo "Quote - policy, should fail"
${PREFIX}quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy command code - quote"
${PREFIX}policycommandcode -ha 03000000 -cc 158 > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000 - should fail"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkFailure $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkSuccess $?

echo "Flush the policy session 03000000"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush the signing key 80000001 "
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Template"
echo ""

# create template hash

# run createprimary -si -v, extract template 

# policies/policytemplate.txt

# 00 01 00 0b 00 04 04 72 00 00 00 10 00 10 08 00 
# 00 00 00 00 00 00

# policymaker -if policies/policytemplate.txt -pr -of policies/policytemplate.bin -nz
# -nz says do not extend, just hash the hexascii line
# yields a template hash for policytemplate

# ef 64 da 91 18 fc ac 82 f4 36 1b 28 84 28 53 d8 
# aa f8 7d fc e1 45 e9 25 cf fe 58 68 aa 2d 22 b6 

# prepend the command code 00000190 to ef 64 ... and construct the actual object policy
# policymaker -if policies/policytemplatehash.txt -pr -of policies/policytemplatehash.bin

# fb 94 b1 43 e5 2b 07 95 b7 ec 44 37 79 99 d6 47 
# 70 1c ae 4b 14 24 af 5a b8 7e 46 f2 58 af eb de 

echo ""
echo "Policy Template with TPM2_Create"
echo ""

echo "Create a primary storage key policy template, 80000001"
${PREFIX}createprimary -hi p -pol policies/policytemplatehash.bin > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create signing key under primary key"
${PREFIX}create -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
checkSuccess $?

echo ""
echo "Policy Template with TPM2_CreateLoaded"
echo ""

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create loaded signing key under primary key"
${PREFIX}createloaded -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush the primary key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the created key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo ""
echo "Policy Template with TPM2_CreatePrimary"
echo ""

echo "Set primary policy for platform hierarchy"
${PREFIX}setprimarypolicy -hi p -halg sha256 -pol policies/policytemplatehash.bin > run.out
checkSuccess $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create loaded primary signing key policy template, 80000001"
${PREFIX}createprimary -si -hi p -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the primary key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?




rm -f tmppriv.bin
rm -f tmppub.bin

