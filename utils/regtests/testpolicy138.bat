REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testpolicy138.sh 793 2016-11-10 21:27:40Z kgoldman $	#
REM #										#
REM # (c) Copyright IBM Corporation 2016					#
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
REM 
REM # Policy command code - sign
REM 
REM # cc69 18b2 2627 3b08 f5bd 406d 7f10 cf16
REM # 0f0a 7d13 dfd8 3b77 70cc bcd1 aa80 d811
REM 
REM # NV index name after written
REM 
REM # 000b 
REM # 5e8e bdf0 4581 9419 070c 7d57 77bf eb61 
REM # ffac 4996 ea4b 6fba de6d a42b 632d 4918   
REM 
REM # Policy Authorize NV with above Name
REM                               
REM # 66 1f a1 02 db cd c2 f6 a0 61 7b 33 a0 ee 6d 95 
REM # ab f6 2c 76 b4 98 b2 91 10 0d 30 91 19 f4 11 fa 
REM 
REM # Policy in NV index 01000000
REM # signing key 80000001 

setlocal enableDelayedExpansion

echo ""
echo "Policy Authorize NV"
echo ""

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key, policyauthnv"
%TPM_EXE_PATH%create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizenv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Define Space"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -sz 50 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
    
echo "NV not written, policyauthorizenv - should fail"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Write algorithm ID into NV index 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -off 0 -if policies/sha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write policy command code sign into NV index 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -off 2 -if policies/policyccsign.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be cc 69 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 66 1f ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy and wrong password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - policy, should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - quote"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 158 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000 - should fail"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policy session 03000000"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key 80000001 "
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template"
echo ""

REM # create template hash
REM 
REM # run createprimary -si -v, extract template 
REM 
REM # policies/policytemplate.txt
REM 
REM # 00 01 00 0b 00 04 04 72 00 00 00 10 00 10 08 00 
REM # 00 00 00 00 00 00
REM 
REM # policymaker -if policies/policytemplate.txt -pr -of policies/policytemplate.bin -nz
REM # -nz says do not extend, just hash the hexascii line
REM # yields a template hash for policytemplate
REM 
REM # ef 64 da 91 18 fc ac 82 f4 36 1b 28 84 28 53 d8 
REM # aa f8 7d fc e1 45 e9 25 cf fe 58 68 aa 2d 22 b6 
REM 
REM # prepend the command code 00000190 to ef 64 ... and construct the actual object policy
REM # policymaker -if policies/policytemplatehash.txt -pr -of policies/policytemplatehash.bin
REM 
REM # fb 94 b1 43 e5 2b 07 95 b7 ec 44 37 79 99 d6 47 
REM # 70 1c ae 4b 14 24 af 5a b8 7e 46 f2 58 af eb de 

echo ""
echo "Policy Template with TPM2_Create"
echo ""

echo "Create a primary storage key policy template, 80000001"
%TPM_EXE_PATH%createprimary -hi p -pol policies/policytemplatehash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create signing key under primary key"
%TPM_EXE_PATH%create -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template with TPM2_CreateLoaded"
echo ""

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create loaded signing key under primary key"
%TPM_EXE_PATH%createloaded -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the created key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template with TPM2_CreatePrimary"
echo ""

echo "Set primary policy for platform hierarchy"
%TPM_EXE_PATH%setprimarypolicy -hi p -halg sha256 -pol policies/policytemplatehash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create loaded primary signing key policy template, 80000001"
%TPM_EXE_PATH%createprimary -si -hi p -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmppriv.bin
rm -f tmppub.bin

