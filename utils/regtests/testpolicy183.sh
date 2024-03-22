#!/bin/bash

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2024					        #
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

# PolicyParameters use case: An NV bits index has 64 bits. Each bit is
# separately authorized using a policy term. The policy uses a
# policyparameters term including the bit being set and a policysigned
# term so that each bit can be authorized using a different
# authorization signing key.
#
# In this example, a 4 sets of 8 terms are created, but the example
# can be extended to 64 bits with a third level of policyor.
#
# For example, the term for setting bit 0 is:
#
# policycommandcode = setbits & policyparameters = bit 0 & policy signed key A
#
# In this example, the authorizor signs the session nonce so the
# signature can only be used in that session, but a signature that
# lasts forever is probably satisfactory.
#
# Note that, either way, the signer is not signing a particular NV
# index. The signature is valid for any index that has the signer's
# public key in the policy.
#
# Since this regression test only has one signing key, it is used for
# bit 0 and an invalid policy digest is used for the other 31 untested
# terms.
#
# See the testpolicy.sh policy signed term calculation:
#
# The policyparameters hash is calculated using:
# nvsetbits -ha 01000000 -bit 0 -phash sha256 policies/policyparameterssha256.bin
# 5e72efd556d9029451cdaa3692f26832d1a143723cb9e9c0ef1c153c398effb8
#
# policyparametersnvsetbitsone.txt:
# 0000016C00000135
# 0000019C5e72efd556d9029451cdaa3692f26832d1a143723cb9e9c0ef1c153c398effb8
# 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# (add a blank space for policyRef)
#
# > policymaker -if policies/policyparametersnvsetbitsone.txt -pr -v -ns -of policies/policyparametersnvsetbitsone.bin
# intermediate policy digest length 32
#  cd da 9e ef 6c 8e 0e a8 92 dc f6 fd 0e a1 c9 7b
#  96 43 67 aa db e3 a1 c5 29 31 87 f1 4e 19 f6 70
#  intermediate policy digest length 32
#  ce 1b ee b6 ba 47 21 d2 26 39 2b c5 5a 9b 45 7e
#  9c 92 96 61 69 c5 c0 80 33 e7 fc db e9 35 11 b3
#  intermediate policy digest length 32
#  38 58 47 f6 34 26 e7 44 df 00 3d b6 76 00 3a 93
#  fb 75 da 93 a4 7d 6e ad 62 1f 92 e6 80 96 10 0b
#  intermediate policy digest length 32
#  26 4e 8c d3 fc 62 96 93 8e 53 71 64 bc 23 a6 43
#  32 29 39 e9 6b 58 b9 06 e3 af 10 0e 57 f6 70 33
#  policy digest length 32
#  26 4e 8c d3 fc 62 96 93 8e 53 71 64 bc 23 a6 43
#  32 29 39 e9 6b 58 b9 06 e3 af 10 0e 57 f6 70 33
# policy digest:
# 264e8cd3fc6296938e537164bc23a643322939e96b58b906e3af100e57f67033
#
# For the other 31 use the invalid digest sha256aaa.bin
# 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
#
# Create an OR term with 1 valid and 7 invalid terms
# > policymaker -if policies/policyor1.txt -pr -v -ns -of policies/policyor1.bin
# c26d8a16aa6099ba9d73cf9846b83b398d48b93ded3bb5ddfc1dfcb43b3a6e55
#
# Create an OR term with 8 invalid terms, used 3 times for 24 bits
# > policymaker -if policies/policyor2-8.txt -pr -v -ns -of policies/policyor2-8.bin
# 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
#
# Finally the set no bits term
# Add 33rd term to set no bits to initialize the index with all zeros:
#
# policycommandcode = setbits & policyparameters = zero
# nvsetbits -ha 01000000 -phash sha256 policies/policyparametersnonesha256.bin
# afd0a346eedaf99a8664f449111941f4bf6966384b296b0e6bfd211064a9c093
#
# Create the command code = nvsetbits, parameters = no bits policy
# 0000016C00000135
# 0000019Cafd0a346eedaf99a8664f449111941f4bf6966384b296b0e6bfd211064a9c093
# > policymaker -if policies/policynvsetbitsnone.txt -pr -v -ns -of policies/policynvsetbitsnone.bin
# intermediate policy digest length 32
#  cd da 9e ef 6c 8e 0e a8 92 dc f6 fd 0e a1 c9 7b
#  96 43 67 aa db e3 a1 c5 29 31 87 f1 4e 19 f6 70
#  intermediate policy digest length 32
#  24 ee a9 56 ef 36 d8 36 c9 56 99 b0 79 b5 42 01
#  f7 5a e7 aa f9 ad 70 a3 15 df 8f 43 aa e4 d5 e8
#  policy digest length 32
#  24 ee a9 56 ef 36 d8 36 c9 56 99 b0 79 b5 42 01
#  f7 5a e7 aa f9 ad 70 a3 15 df 8f 43 aa e4 d5 e8
# policy digest:
# 24eea956ef36d836c95699b079b54201f75ae7aaf9ad70a315df8f43aae4d5e8
#
# Now OR the 4 OR terms and the 33rd term to calculate the final policy
# c26d8a16aa6099ba9d73cf9846b83b398d48b93ded3bb5ddfc1dfcb43b3a6e55
# 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
# 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
# 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
# 24eea956ef36d836c95699b079b54201f75ae7aaf9ad70a315df8f43aae4d5e8
# > policymaker -if policies/policyparametersor9.txt -pr -v -ns -of policies/policyparametersor9.bin
# ad53f79046f9fa1aa7008513da65fd7fae1c186fe8c6ee96160ab6cf844de362

echo ""
echo "Policy Rev 183"
echo ""

echo "nvdefinespace 01000000"
${PREFIX}nvdefinespace -ha 01000000 -hi p -ty b -at aw -pol policies/policyparametersor9.bin > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -on tmpnonce.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "nvsetbits set no bits"
echo ""

echo "Policy command code nvsetbits"
${PREFIX}policycommandcode -ha 03000000 -cc 135 > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy Parameters, no bits"
${PREFIX}policyparameters -ha 03000000 -ph policies/policyparametersnonesha256.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR of ORs, 4 * 8 for the bits + 1 for the no bits term"
${PREFIX}policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV setbits to set written"
${PREFIX}nvsetbits -ha 01000000 -se0 03000000 0 > run.out
checkSuccess $?

echo ""
echo "nvsetbits set bit 0"
echo ""

echo "Start a policy session"
${PREFIX}startauthsession -se p -on tmpnonce.bin > run.out
checkSuccess $?

echo "Policy command code nvsetbits"
${PREFIX}policycommandcode -ha 03000000 -cc 135 > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy Parameters, bit 0"
${PREFIX}policyparameters -ha 03000000 -ph policies/policyparameterssha256.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Load external just the public part of PEM at 80000001"
${PREFIX}loadexternal -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem -ns > run.out
checkSuccess $?

echo "Policy signed, sign with PEM key, sign the policy session nonce"
${PREFIX}policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -in tmpnonce.bin -halg sha256 -pwdk rrrr > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR of 1 bit 0 term and 1-7 placeholder terms"
${PREFIX}policyor -ha 03000000 \
	 -if policies/policyparametersnvsetbitsone.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR of ORs, 4 * 8 for the bits + 1 for the no bits term"
${PREFIX}policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV setbits to set bit 0"
${PREFIX}nvsetbits -ha 01000000 -bit 0 -se0 03000000 0 > run.out
checkSuccess $?

echo ""
echo "nvsetbits set bit 1, should fail"
echo ""

echo "Start a policy session"
${PREFIX}startauthsession -se p -on tmpnonce.bin > run.out
checkSuccess $?

echo "Policy command code nvsetbits"
${PREFIX}policycommandcode -ha 03000000 -cc 135 > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy Parameters"
${PREFIX}policyparameters -ha 03000000 -ph policies/policyparameterssha256.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy signed, sign with PEM key"
${PREFIX}policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg sha256 -pwdk rrrr > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR of 1 bit 0 term and 1-7 terms"
${PREFIX}policyor -ha 03000000 \
	 -if policies/policyparametersnvsetbitsone.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 -if policies/sha256aaa.bin \
	 > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR or ORs, 4 * 8 for the bits + 1 for the no bits term"
${PREFIX}policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV setbits to set bit 0"
${PREFIX}nvsetbits -ha 01000000 -bit 1 -se0 03000000 0 > run.out
checkFailure $?

# cleanup

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "nvundefinespace 01000000"
${PREFIX}nvundefinespace -ha 01000000 -hi p > run.out
checkSuccess $?

rm -f tmpnonce.bin

