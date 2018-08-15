#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testcredential.sh 328 2015-06-09 18:26:00Z kgoldman $		#
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

# primary key 80000000
# storage key 80000001
# signing key 80000002
# policy session 03000000
# e5 87 c1 1a b5 0f 9d 87 30 f7 21 e3 fe a4 2b 46 
# c0 45 5b 24 6f 96 ae e8 5d 18 eb 3b e6 4d 66 6a 

echo ""
echo "Credential"
echo ""

echo "Use a random number as the credential input"
${PREFIX}getrandom -by 32 -of tmpcredin.bin > run.out
checkSuccess $?

echo "Load the storage key under the primary key, 80000001"
${PREFIX}load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp sto > run.out
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

rm tmprpub.bin
rm tmprpriv.bin
rm tmpcredin.bin
rm tmpcredenc.bin
rm tmpcreddec.bin
rm tmpsecret.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
