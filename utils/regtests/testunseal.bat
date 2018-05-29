REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testunseal.bat 1215 2018-05-15 13:13:46Z kgoldman $	#
REM #										#
REM # (c) Copyright IBM Corporation 2015, 2017					#
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

echo ""
echo "Seal and Unseal to Password"
echo ""

echo "Create a sealed data object"
%TPM_EXE_PATH%create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the sealed data object"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Unseal the data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Unseal with bad password - should fail"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Flush the sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Create a primary sealed data object"
%TPM_EXE_PATH%createprimary -bl -kt f -kt p -pwdk seap -if msg.bin  > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the primary data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd seap -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the primary sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Seal and Unseal to PolicySecret Platform Auth"
echo ""

REM # policy is policy secret pointing to platform auth
REM # 000001514000000C plus newline for policyRef

echo "Change platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Create a sealed data object with policysecret platform auth under primary key"
%TPM_EXE_PATH%create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load the sealed data object under primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the data blob - policy failure, policysecret not run"
%TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Policy Secret with PWAP session and platform auth"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Change platform hierarchy auth back to null"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

REM SHA-1

REM extend of aaa + 0 pad to digest length
REM 1d 47 f6 8a ce d5 15 f7 79 73 71 b5 54 e3 2d 47 
REM 98 1a a0 a0 

REM paste that with no white space to file policypcr16aaasha1.txt

REM create AND term for policy PCR, PCR 16
REM > policymakerpcr -halg sha1 -bm 10000 -if policies/policypcr16aaasha1.txt -v -pr -of policies/policypcr.txt
REM 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d

REM convert to binary policy
REM > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcr16aaasha1.bin -pr -v
REM 12 b6 dd 16 43 82 ca e4 5d 0e d0 7f 9e 51 d1 63 
REM a4 24 f5 f2 

REM SHA-256

REM extend of aaa + 0 pad to digest length
REM > pcrextend -ha 16 -if policies/aaa > run.out

REM read the PCR 16 value back
REM > pcrread -ha 16 -ns
REM c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb

REM paste that with no white space to file policypcr16aaasha256.txt

REM create AND term for policy PCR, PCR 16
REM > policymakerpcr -bm 10000 -if policies/policypcr16aaasha256.txt -v -pr -of policies/policypcr.txt
REM 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13

REM convert to binary policy
REM > policymaker -if policies/policypcr.txt -of policies/policypcr16aaasha256.bin -pr -v
REM 76 44 f6 11 ea 10 d7 60 da b9 36 c3 95 1e 1d 85 
REM ec db 84 ce 9a 79 03 dd e1 c7 e0 a2 d9 09 a0 13 

REM sealed blob    80000001
REM policy session 03000000

echo ""
echo "Seal and Unseal to PCRs"
echo ""

for %%H in (sha1 sha256 ) do (

    echo "Create a sealed data object %%H"
    %TPM_EXE_PATH%create -hp 80000000 -nalg %%H -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policypcr16aaa%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the sealed data object"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session %%H"
    %TPM_EXE_PATH%startauthsession -se p -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR 16 Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob - policy failure, policypcr not run"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the wrong PCR 16 value"
    %TPM_EXE_PATH%policypcr -halg %%H -ha 03000000 -bm 10000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob - policy failure, PCR 16 incorrect"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Extend PCR 16 to correct value"
    %TPM_EXE_PATH%pcrextend -halg %%H -ha 16 -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy restart, set back to zero"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the correct PCR 16 value"
    %TPM_EXE_PATH%policypcr -halg %%H -ha 03000000 -bm 10000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed object"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
    
    echo "Flush the policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "Import and Unseal"
echo ""

REM # primary key P1 80000000
REM # sealed data S1 80000001 originally under 80000000
REM # target storage key K1 80000002

for %%A in ("" "ecc") do (

    echo "Create a sealed data object S1 under the primary key P1 80000000"
    %TPM_EXE_PATH%create -hp 80000000 -bl -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sea -if msg.bin -pol policies/policyccduplicate.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the sealed data object S1 at 80000001"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the %%~A storage key K1 80000002"
    %TPM_EXE_PATH%load -hp 80000000 -ipr store%%~Apriv.bin -ipu store%%~Apub.bin -pwdp pps > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session 03000000"
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

    echo "Duplicate sealed data object S1 80000001 under %%~A K1 80000002"
    %TPM_EXE_PATH%duplicate -ho 80000001 -pwdo sig -hp 80000002 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the original S1 to free object slot for import"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Import S1 under %%~A K1 80000002"
    %TPM_EXE_PATH%import -hp 80000002 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv1.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the duplicated sealed data object S1 at 80000001 under %%~A K1 80000002"
    %TPM_EXE_PATH%load -hp 80000002 -ipr tmppriv1.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob"
    %TPM_EXE_PATH%unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed data object at 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the storage key at 80000002"
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

rm tmppriv.bin
rm tmppub.bin
rm tmp.bin
rm tmpdup.bin
rm tmpss.bin
rm tmppriv1.bin

exit /B 0

REM getcapability -cap 1 -pr 80000000
