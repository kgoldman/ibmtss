REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testdup.bat 919 2017-01-20 15:11:51Z kgoldman $		#
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

setlocal enableDelayedExpansion

REM 80000001 K1 storage key
REM 80000002 K2 signing key to be duplicated
REM 80000002 K2 duplicated
REM 03000000 policy session

REM policy
REM be f5 6b 8c 1c c8 4e 11 ed d7 17 52 8d 2c d9 93 
REM 56 bd 2b bf 8f 01 52 09 c3 f8 4a ee ab a8 e8 a2 

REM used for the name in rewrap

echo ""
echo "Duplication"
echo ""

for %%E in ("" "-salg aes -ik tmprnd.bin") do (

    for %%H in (sha1 sha256 sha384) do (

	echo "Create a signing key K2 under the primary key, with policy"
	%TPM_EXE_PATH%create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccduplicate.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Load the storage key K1"
	%TPM_EXE_PATH%load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Load the signing key K2"
	%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Sign a digest, %%H"
	%TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig  > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify the signature, %%H"
	%TPM_EXE_PATH%verifysignature -hk 80000002 -halg %%H -if policies/aaa -is sig.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Start a policy session"
	%TPM_EXE_PATH%startauthsession -se p > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Policy command code, duplicate"
	%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Get policy digest"
	%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Get random AES encryption key"
	%TPM_EXE_PATH%getrandom -by 16 -of tmprnd.bin > run.out 
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Duplicate K2 under K1, %%~E"
	%TPM_EXE_PATH%duplicate -ho 80000002 -pwdo sig -hp 80000001 -od tmpdup.bin -oss tmpss.bin %%~E -se0 03000000 1 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the original K2 to free object slot for import"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Import K2 under K1, %%~E"
	%TPM_EXE_PATH%import -hp 80000001 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin %%~E -opr tmppriv.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Sign under K2, %%H - should fail"
	%TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig > run.out
    	IF !ERRORLEVEL! EQU 0 (
       	    exit /B 1
    	)

	echo "Load the duplicated signing key K2"
	%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Sign using duplicated K2, %%H"
	%TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify the signature, %%H"
	%TPM_EXE_PATH%verifysignature -hk 80000002 -halg %%H -if policies/aaa -is sig.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the duplicated K2"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the parent K1"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the session"
	%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

    )
)

echo ""
echo "Import PEM RSA"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (
    for %%H in (sha1 sha256) do (

	echo "Import the signing key under the primary key %%H"
	%TPM_EXE_PATH%importpem -hp 80000000 -pwdp pps -ipem tmpprivkey.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Load the TPM signing key"
	%TPM_EXE_PATH%load -hp 80000000 -pwdp pps -ipu tmppub.bin -ipr tmppriv.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Sign the message %%H  %%~S"
	%TPM_EXE_PATH%sign -hk 80000001 -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg %%H  %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify the signature %%H"
	%TPM_EXE_PATH%verifysignature -hk 80000001 -if policies/aaa -is tmpsig.bin -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the signing key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

   )
)

echo ""
echo "Import PEM EC "
echo ""

echo "generate the signing key with openssl"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -aes256 -passout pass:rrrr -text > tmpecprivkey.pem

for %%S in ("" "-se0 02000000 1") do (
    for %%H in (sha1 sha256) do (

	echo "Import the signing key under the primary key %%H"
	%TPM_EXE_PATH%importpem -hp 80000000 -pwdp pps -ipem tmpecprivkey.pem -ecc -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Load the TPM signing key"
	%TPM_EXE_PATH%load -hp 80000000 -pwdp pps -ipu tmppub.bin -ipr tmppriv.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Sign the message %%H %%~S"
	%TPM_EXE_PATH%sign -hk 80000001 -ecc -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg %%H %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify the signature %%H"
	%TPM_EXE_PATH%verifysignature -hk 80000001 -ecc -if policies/aaa -is tmpsig.bin -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Flush the signing key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)
   )
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Rewrap"
echo ""

REM duplicate object O1 to K1 (the outer wrapper, knows inner wrapper)
REM rewrap O1 from K1 to K2 (does not know inner wrapper)
REM import O1 to K2 (knows inner wrapper)

REM 03000000 policy session for duplicate
    
REM at TPM 1, duplicate object to K1 outer wrapper, AES wrapper

echo "Create a storage key K2"
%TPM_EXE_PATH%create -hp 80000000 -st -kt f -kt p -opr tmpk2priv.bin -opu tmpk2pub.bin -pwdp pps -pwdk k2 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the storage key K1 80000001 public key "
%TPM_EXE_PATH%loadexternal -hi p -ipu storepub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key O1 with policy"
%TPM_EXE_PATH%create -hp 80000000 -si -opr tmpsignpriv.bin -opu tmpsignpub.bin -pwdp pps -pwdk sig -pol policies/policyccduplicate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key O1 80000002 under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpsignpriv.bin -ipu tmpsignpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save the signing key O1 name"
cp h80000002.bin tmpo1name.bin

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code, duplicate"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get random AES encryption key"
%TPM_EXE_PATH%getrandom -by 16 -of tmprnd.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Duplicate O1 80000002 under K1 80000001 outer wrapper, using AES inner wrapper"
%TPM_EXE_PATH%duplicate -ho 80000002 -pwdo sig -hp 80000001 -ik tmprnd.bin -od tmpdup.bin -oss tmpss.bin -salg aes -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key O1 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush storage key K1 80000001 public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM at TPM 2

echo "Load storage key K1 80000001 public and private key"
%TPM_EXE_PATH%load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load storage key K2 80000002 public key"
%TPM_EXE_PATH%loadexternal -hi p -ipu tmpk2pub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Rewrap O1 from K1 80000001 to K2 80000002 "
%TPM_EXE_PATH%rewrap -ho 80000001 -hn 80000002 -pwdo sto -id tmpdup.bin -in tmpo1name.bin -iss tmpss.bin -od tmpdup.bin -oss tmpss.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush old key K1 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush new key K2 80000002 public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM at TPM 3

echo "Load storage key K2 80000001 public key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpk2priv.bin -ipu tmpk2pub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Import rewraped O1 to K2"
%TPM_EXE_PATH%import -hp 80000001 -pwdp k2 -ipu tmpsignpub.bin -id tmpdup.bin -iss tmpss.bin -salg aes -ik tmprnd.bin -opr tmpsignpriv3.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the imported signing key O1 80000002 under K2 80000001"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmpsignpriv3.bin -ipu tmpsignpub.bin -pwdp k2 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign using duplicated K2"
%TPM_EXE_PATH%sign -hk 80000002  -if policies/aaa -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -if policies/aaa -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush storage key K2 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key O1 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpo1name.bin
rm -f tmpsignpriv.bin
rm -f tmpsignpub.bin
rm -f tmprnd.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmpsignpriv3.bin
rm -f sig.bin
rm -f tmpk2priv.bin
rm -f tmpk2pub.bin
rm -f tmposs.bin 
rm -f tmpprivkey.pem
rm -f tmpecprivkey.pem
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpsig.bin

exit /B 0

REM flushcontext -ha 80000001
REM flushcontext -ha 80000002
REM flushcontext -ha 03000000

REM getcapability -cap 1 -pr 80000000
REM getcapability -cap 1 -pr 03000000
