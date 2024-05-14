REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2024					#
REM # 										#
REM # All rights reserved.							#
REM # 										#
REM # Redistribution and use in source and binary forms, with or without	#
REM # modification, are permitted provided that the following conditions are	#
REM # met:									#
REM # 										#
REM # Redistributions of source code must retain the above copyright notice,	#
REM # this list of conditions and the following disclaimer.			#
REM # 										#
REM # Redistributions in binary form must reproduce the above copyright		#
REM # notice, this list of conditions and the following disclaimer in the	#
REM # documentation and/or other materials provided with the distribution.	#
REM # 										#
REM # Neither the names of the IBM Corporation nor the names of its		#
REM # contributors may be used to endorse or promote products derived from	#
REM # this software without specific prior written permission.			#
REM # 										#
REM # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS	#
REM # "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
REM # LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	#
REM # A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT	#
REM # HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
REM # SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
REM # LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	#
REM # DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	#
REM # THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT	#
REM # (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	#
REM # OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.	#
REM #										#
REM #############################################################################

REM # used for the name in policy ticket

REM if [ -z $TPM_DATA_DIR ]; then
REM     TPM_DATA_DIR=.
REM fi

setlocal enableDelayedExpansion

REM # PolicyParameters use case: An NV bits index has 64 bits. Each bit is
REM # separately authorized using a policy term. The policy uses a
REM # policyparameters term including the bit being set and a policysigned
REM # term so that each bit can be authorized using a different
REM # authorization signing key.
REM #
REM # In this example, a 4 sets of 8 terms are created, but the example
REM # can be extended to 64 bits with a third level of policyor.
REM #
REM # For example, the term for setting bit 0 is:
REM #
REM # policycommandcode = setbits & policyparameters = bit 0 & policy signed key A
REM #
REM # In this example, the authorizor signs the session nonce so the
REM # signature can only be used in that session, but a signature that
REM # lasts forever is probably satisfactory.
REM #
REM # Note that, either way, the signer is not signing a particular NV
REM # index. The signature is valid for any index that has the signer's
REM # public key in the policy.
REM #
REM # Since this regression test only has one signing key, it is used for
REM # bit 0 and an invalid policy digest is used for the other 31 untested
REM # terms.
REM #
REM # See the testpolicy.sh policy signed term calculation:
REM #
REM # The policyparameters hash is calculated using:
REM # nvsetbits -ha 01000000 -bit 0 -phash sha256 policies/policyparameterssha256.bin
REM # 5e72efd556d9029451cdaa3692f26832d1a143723cb9e9c0ef1c153c398effb8
REM #
REM # policyparametersnvsetbitsone.txt:
REM # 0000016C00000135
REM # 0000019C5e72efd556d9029451cdaa3692f26832d1a143723cb9e9c0ef1c153c398effb8
REM # 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # (add a blank space for policyRef)
REM #
REM # > policymaker -if policies/policyparametersnvsetbitsone.txt -pr -v -ns -of policies/policyparametersnvsetbitsone.bin
REM # intermediate policy digest length 32
REM #  cd da 9e ef 6c 8e 0e a8 92 dc f6 fd 0e a1 c9 7b
REM #  96 43 67 aa db e3 a1 c5 29 31 87 f1 4e 19 f6 70
REM #  intermediate policy digest length 32
REM #  ce 1b ee b6 ba 47 21 d2 26 39 2b c5 5a 9b 45 7e
REM #  9c 92 96 61 69 c5 c0 80 33 e7 fc db e9 35 11 b3
REM #  intermediate policy digest length 32
REM #  38 58 47 f6 34 26 e7 44 df 00 3d b6 76 00 3a 93
REM #  fb 75 da 93 a4 7d 6e ad 62 1f 92 e6 80 96 10 0b
REM #  intermediate policy digest length 32
REM #  26 4e 8c d3 fc 62 96 93 8e 53 71 64 bc 23 a6 43
REM #  32 29 39 e9 6b 58 b9 06 e3 af 10 0e 57 f6 70 33
REM #  policy digest length 32
REM #  26 4e 8c d3 fc 62 96 93 8e 53 71 64 bc 23 a6 43
REM #  32 29 39 e9 6b 58 b9 06 e3 af 10 0e 57 f6 70 33
REM # policy digest:
REM # 264e8cd3fc6296938e537164bc23a643322939e96b58b906e3af100e57f67033
REM #
REM # For the other 31 use the invalid digest sha256aaa.bin
REM # 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
REM #
REM # Create an OR term with 1 valid and 7 invalid terms
REM # > policymaker -if policies/policyor1.txt -pr -v -ns -of policies/policyor1.bin
REM # c26d8a16aa6099ba9d73cf9846b83b398d48b93ded3bb5ddfc1dfcb43b3a6e55
REM #
REM # Create an OR term with 8 invalid terms, used 3 times for 24 bits
REM # > policymaker -if policies/policyor2-8.txt -pr -v -ns -of policies/policyor2-8.bin
REM # 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
REM #
REM # Finally the set no bits term
REM # Add 33rd term to set no bits to initialize the index with all zeros:
REM #
REM # policycommandcode = setbits & policyparameters = zero
REM # nvsetbits -ha 01000000 -phash sha256 policies/policyparametersnonesha256.bin
REM # afd0a346eedaf99a8664f449111941f4bf6966384b296b0e6bfd211064a9c093
REM #
REM # Create the command code = nvsetbits, parameters = no bits policy
REM # 0000016C00000135
REM # 0000019Cafd0a346eedaf99a8664f449111941f4bf6966384b296b0e6bfd211064a9c093
REM # > policymaker -if policies/policynvsetbitsnone.txt -pr -v -ns -of policies/policynvsetbitsnone.bin
REM # intermediate policy digest length 32
REM #  cd da 9e ef 6c 8e 0e a8 92 dc f6 fd 0e a1 c9 7b
REM #  96 43 67 aa db e3 a1 c5 29 31 87 f1 4e 19 f6 70
REM #  intermediate policy digest length 32
REM #  24 ee a9 56 ef 36 d8 36 c9 56 99 b0 79 b5 42 01
REM #  f7 5a e7 aa f9 ad 70 a3 15 df 8f 43 aa e4 d5 e8
REM #  policy digest length 32
REM #  24 ee a9 56 ef 36 d8 36 c9 56 99 b0 79 b5 42 01
REM #  f7 5a e7 aa f9 ad 70 a3 15 df 8f 43 aa e4 d5 e8
REM # policy digest:
REM # 24eea956ef36d836c95699b079b54201f75ae7aaf9ad70a315df8f43aae4d5e8
REM #
REM # Now OR the 4 OR terms and the 33rd term to calculate the final policy
REM # c26d8a16aa6099ba9d73cf9846b83b398d48b93ded3bb5ddfc1dfcb43b3a6e55
REM # 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
REM # 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
REM # 14f10e9f4ef5030741fb2400ccd71cd1bf0cdf68a841103385b041b9f29b9caf
REM # 24eea956ef36d836c95699b079b54201f75ae7aaf9ad70a315df8f43aae4d5e8
REM # > policymaker -if policies/policyparametersor9.txt -pr -v -ns -of policies/policyparametersor9.bin
REM # ad53f79046f9fa1aa7008513da65fd7fae1c186fe8c6ee96160ab6cf844de362

echo ""
echo "Policy Rev 183"
echo ""

echo ""
echo "PolicyParameters"
echo ""

echo "nvdefinespace 01000000"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi p -ty b -at aw -pol policies/policyparametersor9.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on tmpnonce.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "nvsetbits set no bits"
echo ""

echo "Policy command code nvsetbits"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 135 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Parameters, no bits"
%TPM_EXE_PATH%policyparameters -ha 03000000 -ph policies/policyparametersnonesha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR of ORs, 4 * 8 for the bits + 1 for the no bits term"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV setbits to set written"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "nvsetbits set bit 0"
echo ""

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on tmpnonce.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code nvsetbits"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 135 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Parameters, bit 0"
%TPM_EXE_PATH%policyparameters -ha 03000000 -ph policies/policyparameterssha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load external just the public part of PEM at 80000001"
%TPM_EXE_PATH%loadexternal -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy signed, sign with PEM key, sign the policy session nonce"
%TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -in tmpnonce.bin -halg sha256 -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR of 1 bit 0 term and 1-7 placeholder terms"
%TPM_EXE_PATH%policyor -ha 03000000 ^
	 -if policies/policyparametersnvsetbitsone.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR of ORs, 4 * 8 for the bits + 1 for the no bits term"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV setbits to set bit 0"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -bit 0 -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "nvsetbits set bit 1, should fail"
echo ""

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on tmpnonce.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code nvsetbits"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 135 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Parameters"
%TPM_EXE_PATH%policyparameters -ha 03000000 -ph policies/policyparameterssha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy signed, sign with PEM key"
%TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg sha256 -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR of 1 bit 0 term and 1-7 terms"
%TPM_EXE_PATH%policyor -ha 03000000 ^
	 -if policies/policyparametersnvsetbitsone.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 -if policies/sha256aaa.bin ^
	 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR or ORs, 4 * 8 for the bits + 1 for the no bits term"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyor1.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policyor2-8.bin -if policies/policynvsetbitsnone.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV setbits to set bit 0"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -bit 1 -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

REM # cleanup

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "nvundefinespace 01000000"
%TPM_EXE_PATH%nvundefinespace -ha 01000000 -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpnonce.bin

echo ""
echo "PolicyCapability"
echo ""

REM # Test case: Seal to TPM rev 183 or greater

echo "Create a primary sealed data object with policycapability"
%TPM_EXE_PATH%createprimary  -bl -kt f -kt p -uwa -if msg.bin -pol policies/policycaprevision183.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # args = operandb.buffer offset operation capability property

REM # policycapargsrevision183.txt
REM # 000000b7 0000 0007 00000006 00000102
REM #
REM # hash args
REM #
REM # policymaker -nz -if policies/policycapargsrevision183.txt -pr -ns
REM # policy digest length 32
REM # 1e11883c7d42c639c4e4ae1e1fa48b53a2ef6b6387cbeabc97501b1582b3e5a2
REM #
REM # policycaprevision183.txt
REM #
REM # 0000019b1e11883c7d42c639c4e4ae1e1fa48b53a2ef6b6387cbeabc97501b1582b3e5a2
REM #
REM # policymaker -if policies/policycaprevision183.txt -pr -of policies/policycaprevision183.bin
REM # policy digest length 32
REM # 41 82 db 6d 45 1f 28 c9 f8 f3 43 36 91 94 08 48
REM # d7 94 73 84 ec 5d 26 69 cb f5 0b 71 76 89 e2 26

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Capability property TPM_PT_REVISION GE 183 decimal 0xb7"
%TPM_EXE_PATH%policycapability -hs 03000000 -if policies/rev183.bin -op 7 -cap 6 -pr 102 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Unseal the data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # cleanup PolicyCapability

rm -rf tmp.bin
