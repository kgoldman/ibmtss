REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2020					#
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
REM # signing key 80000002test
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
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
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

echo ""
echo "EK Certificate"
echo ""

REM The low EK certificates remain in NV at the end of the test.  This
REM makes the test, when run stand alone, useful for provisioning a TPM.
REM It is not useful when the entire regression test runs, because a
REM later test generates a new EPS (endorsement primary seed), which
REM invalidates the EK and thus the certificate.

REM optional NV index for Policy C
set NVIDX=01c07f01 01c07f02 01c07f03
REM corresponding hash algorithms
set NVHALG=sha256 sha384 sha512
REM NV index policy size includes hash algorithm
set SIZ=34 50 66
REM  algorithms in binary from Algorithm Registry
set HBIN=000b 000c 000d
REM Name from Section B.6.3 Computing Policy Index Names Table 14: Policy Index Names
set NVNAME=    000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f 000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c 000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560


set i=0
for %%v in (!NVIDX!) do set /A i+=1 & set NVIDX[!i!]=%%v
set i=0
for %%h in (!NVHALG!) do set /A i+=1 & set NVHALG[!i!]=%%h
set i=0
for %%s in (!SIZ!) do set /A i+=1 & set SIZ[!i!]=%%s
set i=0
for %%b in (!HBIN!) do set /A i+=1 & set HBIN[!i!]=%%b
set i=0
for %%n in (!NVNAME!) do set /A i+=1 & set NVNAME[!i!]=%%n
set L=!i!

REM clear endorsement auth, may fail

%TPM_EXE_PATH%hierarchychangeauth -hi e -pwda eee > run.out
%TPM_EXE_PATH%dictionaryattacklockreset > run.out

echo ""
echo "High Range Policy NV Index Provisioning"
echo ""

for /L %%j in (1,1,!L!) do (

    echo "Undefine optional NV index !NVIDX[%%j]!"
    %TPM_EXE_PATH%nvundefinespace -ha !NVIDX[%%j]! -hi o > run.out 

    echo "Define optional !NVHALG[%%j]! NV index !NVIDX[%%j]! size !SIZ[%%j]! with PolicySecret for TPM_RH_ENDORSEMENT"
    %TPM_EXE_PATH%nvdefinespace -ha !NVIDX[%%j]! -nalg !NVHALG[%%j]! -hi o -pol policies/policyiwgek!NVHALG[%%j]!.bin -sz !SIZ[%%j]! +at wa +at or +at ppr +at ar -at aw > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a !NVHALG[%%j]! policy session"
    %TPM_EXE_PATH%startauthsession -se p -halg !NVHALG[%%j]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy"
    %TPM_EXE_PATH%policysecret -hs 03000000 -ha 4000000B > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Write the !NVHALG[%%j]! index !NVIDX[%%j]! to set the written bit before reading the Name"
    %TPM_EXE_PATH%nvwrite -ha !NVIDX[%%j]! -if policies/policysecretp!NVHALG[%%j]!ha.bin  -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the !NVHALG[%%j]! Name"
    %TPM_EXE_PATH%nvreadpublic -ha !NVIDX[%%j]! -ns > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the !NVHALG[%%j]! !HBIN[%%j]! Name"
    grep !HBIN[%%j]! run.out > tmp.txt
    grep -v nvreadpublic tmp.txt > tmpactual.txt
    echo !NVNAME[%%j]! > tmpexpect.txt
    diff -w tmpactual.txt tmpexpect.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "High Range EK Certificate"
echo ""

echo "Change endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwdn eee
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Change platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

REM RSA EK certficates
set HALG=sha256 sha384
set CALG=2048 3072
set CIDX=01c00012 01c0001c

set i=0
for %%a in (!HALG!) do set /A i+=1 & set HALG[!i!]=%%a
set i=0
for %%b in (!CALG!) do set /A i+=1 & set CALG[!i!]=%%b
set i=0
for %%c in (!CIDX!) do set /A i+=1 & set CIDX[!i!]=%%c
set L=!i!

for /L %%i in (1,1,!L!) do (

    echo "Create an !{CALG[%%i]! EK certificate"
    %TPM_EXE_PATH%createekcert -high -rsa !CALG[%%i]! -cakey cakey.pem -capwd rrrr -pwdp ppp -pwde eee -of tmp.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the !CALG[%%i]! EK certificate"
    %TPM_EXE_PATH%createek -high -rsa !CALG[%%i]! -ce > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "CreatePrimary 80000001 and validate the !CALG[%%i]! EK against the EK certificate"
    %TPM_EXE_PATH%createek -high -pwde eee -pwdk kkk -rsa !CALG[%%i]! -cp -noflush > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Validate the !CALG[%%i]! EK certificate against the root"
    %TPM_EXE_PATH%createek -high -rsa !CALG[%%i]! -root certificates/rootcerts.windows.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using the password"
    %TPM_EXE_PATH%create -hp 80000001 -si -pwdp kkk > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a !HALG[%%i]! policy session"
    %TPM_EXE_PATH%startauthsession -se p -halg !HALG[%%i]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy A - policysecret with endorsement auth"
    %TPM_EXE_PATH%policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug - 83 71 97 67, 8b bf 22 66, 1e 3b 76 50"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%i]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%i]!.bin -if policies/policyiwgekc!HALG[%%i]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - ca 3d 0a 99, b2 6e 7d 28, b8 22 1c a6"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using Policy A"
    %TPM_EXE_PATH%create -hp 80000001 -si -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy restart !HALG[%%i]! 03000000"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy in NV - policysecret with platform auth"
    %TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - c8 b1 29 2e, b2 84 8c b4"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy Policy C - Policy Authorize NV"
    %TPM_EXE_PATH%policyauthorizenv -ha !NVIDX[%%i]! -hs 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - 37 67 e2 ed, d6 03 2c e6"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%i]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%i]!.bin -if policies/policyiwgekc!HALG[%%i]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - ca 3d 0a 99,  b2 6e 7d 28"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using Policy C"
    %TPM_EXE_PATH%create -hp 80000001 -si -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session !HALG[%%i]! 03000000"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the primary key !CALG[%%i]! 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Undefine !CALG[%%i]! NV index !CIDX[%%i]!"
    %TPM_EXE_PATH%nvundefinespace -ha !CIDX[%%i]! -hi p -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

REM ECC EK certficates
set HALG=sha256 sha384
set CALG=nistp256 nistp384
set CIDX=01c00014 01c00016

REM interate though high range ECC EK certficates.  Both the EK and
REM certificate are removed in each iteration since the TPM resources
REM are limited.

set i=0
for %%a in (!HALG!) do set /A i+=1 & set HALG[!i!]=%%a
set i=0
for %%b in (!CALG!) do set /A i+=1 & set CALG[!i!]=%%b
set i=0
for %%c in (!CIDX!) do set /A i+=1 & set CIDX[!i!]=%%c
set L=!i!

for /L %%i in (1,1,!L!) do (

    echo "Create an !CALG[%%i]! EK certificate"
    %TPM_EXE_PATH%createekcert -high -ecc !CALG[%%i]! -cakey cakeyecc.pem -capwd rrrr -caalg ec -pwdp ppp -pwde eee -of tmp.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the !CALG[%%i]! EK certificate"
    %TPM_EXE_PATH%createek -high -ecc !CALG[%%i]! -ce > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "CreatePrimary 80000001 and validate the !CALG[%%i]! EK against the EK certificate"
    %TPM_EXE_PATH%createek -high -pwde eee -pwdk kkk -ecc !CALG[%%i]! -cp -noflush > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Validate the !CALG[%%i]! EK certificate against the root"
    %TPM_EXE_PATH%createek -high -ecc !CALG[%%i]! -root certificates/rootcerts.windows.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using the password"
    %TPM_EXE_PATH%create -hp 80000001 -si -pwdp kkk > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a !HALG[%%i]! policy session"
    %TPM_EXE_PATH%startauthsession -se p -halg !HALG[%%i]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy A - policysecret with endorsement auth"
    %TPM_EXE_PATH%policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug - 83 71 97 67, 8b bf 22 66"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%i]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%i]!.bin -if policies/policyiwgekc!HALG[%%i]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - ca 3d 0a 99, b2 6e 7d 28"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using Policy A"
    %TPM_EXE_PATH%create -hp 80000001 -si -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy restart !HALG[%%i]! 03000000"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy in NV - policysecret with platform auth"
    %TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - c8 b1 29 2e, b2 84 8c b4"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy Policy C - Policy Authorize NV"
    %TPM_EXE_PATH%policyauthorizenv -ha !NVIDX[%%i]! -hs 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - 37 67 e2 ed, d6 03 2c e6"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%i]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%i]!.bin -if policies/policyiwgekc!HALG[%%i]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%i]! session digest for debug - ca 3d 0a 99,  b2 6e 7d 28"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the !CALG[%%i]! EK using Policy C"
    %TPM_EXE_PATH%create -hp 80000001 -si -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session !HALG[%%i]! 03000000"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the primary key !CALG[%%i]! 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Undefine !CALG[%%i]! NV index !CIDX[%%i]!"
    %TPM_EXE_PATH%nvundefinespace -ha !CIDX[%%i]! -hi p -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "High Range Cleanup"
echo ""

echo "Reset endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwda eee > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Reset platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for /L %%i in (1,1,!L!) do (

    echo "Undefine optional !HALG[%%i]! NV index !NVIDX[%%i]!"
    %TPM_EXE_PATH%nvundefinespace -ha !NVIDX[%%i]! -hi o > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "Low Range EK Certificate"
echo ""

echo "Set platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwdn eee > run.out
checkSuccess $?

for %%A in ("-rsa 2048" "-ecc nistp256") do (

    echo "Create an %%~A EK certificate"
    %TPM_EXE_PATH%createekcert %%~A -cakey cakey.pem -capwd rrrr -pwdp ppp -pwde eee -of tmp.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the %%~A EK certificate"
    %TPM_EXE_PATH%createek %%~A -ce > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the $%%~Atemplate - should fail"
    %TPM_EXE_PATH%createek %%~A -te > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Read the %%~A nonce - should fail"
    %TPM_EXE_PATH%createek %%~A -no > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "CreatePrimary 80000001 and validate the %%~A EK against the EK certificate"
    %TPM_EXE_PATH%createek %%~A -pwde eee -cp -noflush > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Validate the %%~A EK certificate against the root"
    %TPM_EXE_PATH%createek %%~A -root certificates/rootcerts.windows.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy A - policysecret with endorsement auth"
    %TPM_EXE_PATH%policysecret -ha 4000000B -hs 03000000 -pwde eee > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug - 83 71 97 67"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create a signing key under the EK using Policy A"
    %TPM_EXE_PATH%create -hp 80000001 -si -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session 03000000"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the primary key 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo "Clear platform hierarchy auth"
 %TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
 IF !ERRORLEVEL! NEQ 0 (
     exit /B 1
 )

echo "Reset endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwda eee > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

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

REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000

exit /B 0

