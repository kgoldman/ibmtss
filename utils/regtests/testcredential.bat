REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #	$Id: testcredential.sh 328 2015-06-09 18:26:00Z kgoldman $		#
REM #										#
REM # (c) Copyright IBM Corporation 2015					#
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
REM # primary key 80000000
REM # storage key 80000001
REM # signing key 80000002
REM # policy session 03000000
REM # e5 87 c1 1a b5 0f 9d 87 30 f7 21 e3 fe a4 2b 46 
REM # c0 45 5b 24 6f 96 ae e8 5d 18 eb 3b e6 4d 66 6a 

setlocal enableDelayedExpansion

echo ""
echo "Credential"
echo ""

echo "Use a random number as the credential input"
%TPM_EXE_PATH%getrandom -by 32 -of tmpcredin.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the storage key under the primary key, 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a restricted signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -sir -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk sig -pol policies/policyccactivate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key, 80000002"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Encrypt the credential using makecredential"
%TPM_EXE_PATH%makecredential -ha 80000001 -icred tmpcredin.bin -in h80000002.bin -ocred tmpcredenc.bin -os tmpsecret.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - activatecredential"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 00000147 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Activate credential"
%TPM_EXE_PATH%activatecredential -ha 80000002 -hk 80000001 -icred tmpcredenc.bin -is tmpsecret.bin -pwdk sto -ocred tmpcreddec.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Check the decrypted result"
diff tmpcredin.bin tmpcreddec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm tmprpub.bin
rm tmprpriv.bin
rm tmpcredin.bin
rm tmpcredenc.bin
rm tmpcreddec.bin
rm tmpsecret.bin

REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000

exit /B 0
