REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testpolicy.bat 1087 2017-10-24 18:08:49Z kgoldman $	#
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

REM # used for the name in policy ticket

REM if [ -z $TPM_DATA_DIR ]; then
REM     TPM_DATA_DIR=.
REM fi

setlocal enableDelayedExpansion

echo ""
echo "Policy Command Code"
echo ""

echo "Create a signing key under the primary key - policy command code - sign"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccsign.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM sign with correct policy command code

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy and wrong password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail, session used "
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

REM quote with bad policy or bad command 

REM echo "Start a policy session"
REM ./startauthsession -se p > run.out
REM     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - PWAP"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -pwdk sig > run.out
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

REM # echo "Flush the session"
REM # ./flushcontext -ha 03000000 > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )


REM # echo "Start a policy session"
REM # ./startauthsession -se p > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Policy command code - quote"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 158 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

echo "Quote - policy, should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)


REM # echo "Flush the session"
REM # ./flushcontext -ha 03000000 > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Command Code and Policy Password / Authvalue"
echo ""

echo "Create a signing key under the primary key - policy command code - sign, auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccsign-auth.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policypassword

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy password"
%TPM_EXE_PATH%policypassword -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, no password should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest - policy, password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policyauthvalue

REM # echo "Start a policy session"
REM # startauthsession -se p > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM    exit /B 1
REM    )


echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authvalue"
%TPM_EXE_PATH%policyauthvalue -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, no password should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest - policy, password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Password and Policy Authvalue flags"
echo ""

for %%C in (policypassword policyauthvalue) do (


    echo "Create a signing key under the primary key - policy command code - sign, auth"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccsign-auth.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Load the signing key under the primary key"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy command code - sign"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy %%C"
    %TPM_EXE_PATH%%%C -ha 03000000 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Sign a digest - policy, password"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Create a signing key under the primary key - policy command code - sign"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyccsign.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Load the signing key under the primary key"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy command code - sign"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Sign a digest - policy and wrong password"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

)

echo ""
echo "Policy Signed"
echo ""

REM # create rsaprivkey.pem
REM # > openssl genrsa -out rsaprivkey.pem -aes256 -passout pass:rrrr 2048
REM # extract the public key
REM # > openssl pkey -inform pem -outform pem -in rsaprivkey.pem -passin pass:rrrr -pubout -out rsapubkey.pem 
REM # sign a test message msg.bin
REM # > openssl dgst -sha1 -sign rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin
REM #
REM # create the policy:
REM # after loadexternal, get the name from readpublic -ho 80000001 -v
REM 
REM # sha1
REM # 00 04 42 34 c2 4f c1 b9 de 66 93 a6 24 53 41 7d 
REM # 27 34 d7 53 8f 6f 
REM 
REM # sha256
REM # 00 0b 64 ac 92 1a 03 5c 72 b3 aa 55 ba 7d b8 b5 
REM # 99 f1 72 6f 52 ec 2f 68 20 42 fc 0e 0d 29 fa e8 
REM # 17 99 
REM 
REM # 00000160 plus the above name as text, add a blank line for empty policyRef
REM # to create policies/policysigned%%H.txt
REM #
REM # 0000016000044234c24fc1b9de6693a62453417d2734d7538f6f
REM # 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM #
REM # makes sha256 policy by default, policy digest algorithm is separate from Name and signature hash algorithm
REM #
REM # > policymaker -if policies/policysigned%%H.txt -of policies/policysigned%%H.bin -pr
REM #
REM # 9d 81 7a 4e e0 76 eb b5 cf ee c1 82 05 cc 4c 01 
REM # b3 a0 5e 59 a9 b9 65 a1 59 af 1e cd 3d bf 54 fb 
REM #
REM # de bf 9d fa 3c 98 08 0b f1 7d d1 d0 7b 54 fd e1 
REM # 07 93 7f e5 40 50 9e 70 96 aa 73 27 53 b3 83 31 
REM #
REM # 80000000 primary key
REM # 80000001 verification public key
REM # 80000002 signing key with policy
REM # 03000000 policy session

for %%H in (sha1 sha256) do (

    echo "Load external just the public part of PEM at 80000001 - %%H"
    %TPM_EXE_PATH%loadexternal -halg %%H -nalg %%H -ipem policies/rsapubkey.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a test message with openssl - %%H"
    openssl dgst -%%H -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin

    echo "Verify the signature with 80000001 - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if msg.bin -is pssig.bin -raw > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Create a signing key under the primary key - policy signed - %%H"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policysigned%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Load the signing key under the primary key at 80000002"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy, should fail"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
    exit /B 1
    )

    echo "Policy signed - sign with PEM key - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg %%H -pwdk rrrr > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Get policy digest, should be f877 ..."
    %TPM_EXE_PATH%policygetdigest -ha 03000000 -of tmppol.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

     echo "Policy restart, set back to zero"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign just expiration (uint32_t 4 zeros) with openssl - %%H"
    openssl dgst -%%H -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/zero4.bin

    echo "Policy signed, signature generated externally - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -halg %%H -is pssig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session - save nonceTPM"
    %TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Policy signed with nonceTPM and expiration, create a ticket - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg %%H -pwdk rrrr -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Policy ticket"
    %TPM_EXE_PATH%policyticket -ha 03000000 -to to.bin -na h80000001.bin -tk tkt.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy ticket"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Flush the verification public key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Flush the signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

)

REM # getcapability  -cap 1 -pr 80000000
REM # getcapability  -cap 1 -pr 02000000
REM # getcapability  -cap 1 -pr 03000000

REM # exit 0

echo ""
echo "Policy Secret"
echo ""

REM # 4000000c platform
REM # 80000000 primary key
REM # 80000001 signing key with policy
REM # 03000000 policy session
REM # 02000001 hmac session

echo "Change platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret using platform auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session, create a ticket"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret using primary key, create a ticket"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy ticket"
%TPM_EXE_PATH%policyticket -ha 03000000 -to to.bin -hi p -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy ticket"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with HMAC session"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -se0 02000001 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change platform hierarchy auth back to null"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Secret with NV Auth"
echo ""

REM Name is 
REM 00 0b e0 65 10 81 c2 fc da 30 69 93 da 43 d1 de 
REM 5b 24 be 42 6e 2d 61 90 7b 42 83 54 69 13 6c 97 
REM 68 1f 
REM
REM Policy is
REM c6 93 f9 b0 ef 1a b7 1e ca ae 00 af 1f 0b f4 88 
REM 37 9e ab 16 c1 f8 0d 9f f9 6d 90 41 4e 2f c6 b3 

echo "NV Define Space 0100000"
%TPM_EXE_PATH%nvdefinespace -hi p -ha 01000000 -pwdn nnn -sz 16 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret NV auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policysecretnv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 01000000 -hs 03000000 -pwde nnn -in noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space 0100000"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Secret with Object"
echo ""

REM # Use a externally generated object so that the Name is known and thus
REM # the policy can be precalculated

REM # Name
REM # 00 0b 64 ac 92 1a 03 5c 72 b3 aa 55 ba 7d b8 b5 
REM # 99 f1 72 6f 52 ec 2f 68 20 42 fc 0e 0d 29 fa e8 
REM # 17 99 

REM # 000001151 plus the above name as text, add a blank line for empty policyRef
REM # to create policies/policysecretsha256.txt
REM # 00000151000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799

REM # 4b 7f ca c2 b7 c3 ac a2 7c 5c da 9c 71 e6 75 28 
REM # 63 d2 87 d2 33 ec 49 0e 7a be 88 f1 ef 94 5d 5c 

echo "Load the RSA openssl key pair in the NULL hierarchy 80000001"
%TPM_EXE_PATH%loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret of object 80000001"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -uwa -pol policies/policysecretsha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key 80000002"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - password auth - should fail"
%TPM_EXE_PATH%sign -hk 80000002 -if policies/aaa -pwdk sig > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policysecret key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the RSA openssl key pair in the NULL hierarchy, userWithAuth false 80000001"
%TPM_EXE_PATH%loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr -uwa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session - should fail"
%TPM_EXE_PATH%policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policysecret key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Authorize"
echo ""

REM # 80000000 primary
REM # 80000001 verification public key, openssl
REM # 80000002 signing key
REM # 03000000 policy session

REM # Name for 80000001 0004 4234 c24f c1b9 de66 93a6 2453 417d 2734 d753 8f6f
REM #
REM # policyauthorize.txt
REM # 0000016a00044234c24fc1b9de6693a62453417d2734d7538f6f
REM #
REM # (need blank line for policyRef)
REM #
REM # > policymaker -if policies/policyauthorize.txt -of policies/policyauthorize.bin -pr
REM #
REM # 46 d4 8c 7e 17 0a 71 ca 9e 1f c7 e1 77 e5 7b 53 
REM # 75 df c4 3a 44 c9 65 4b 18 97 ce b1 92 e0 21 50 

echo "Create a signing key with policy authorize"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyauthorize.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load external just the public part of PEM authorizing key"
%TPM_EXE_PATH%loadexternal -hi p -halg sha1 -nalg sha1 -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be zero"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policy to approve, aHash input"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Openssl generate aHash"
openssl dgst -sha1 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policyapproved.bin

echo "Verify the signature to generate ticket"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha1 -if policyapproved.bin -is pssig.bin -raw -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authorize using the ticket"
%TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policyapproved.bin -skn h80000001.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policy authorize"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the verification public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # getcapability  -cap 1 -pr 80000000
REM # getcapability  -cap 1 -pr 02000000
REM # getcapability  -cap 1 -pr 03000000

REM # exit 0

echo ""
echo "Set Primary Policy"
echo ""

echo "Platform policy empty"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy empty, bad password"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Set platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy empty, bad password"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Platform policy empty"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy to policy secret platform auth"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp -halg sha256 -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change platform hierarchy auth to null with policy secret"
%TPM_EXE_PATH%hierarchychangeauth -hi p -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy PCR no select"
echo ""

REM # create AND term for policy PCR
REM # > policymakerpcr -halg sha1 -bm 0 -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000403000000da39a3ee5e6b4b0d3255bfef95601890afd80709
REM 
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcrbm0.bin -pr -v
REM 
REM # 6d 38 49 38 e1 d5 8b 56 71 92 55 94 3f 06 69 66 
REM # b6 fa 2c 23 

echo "Create a signing key with policy PCR no select"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -nalg sha1 -pol policies/policypcrbm0.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -halg sha1 -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 6d 38 49 38 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should succeed"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR extend PCR 0, updates pcr counter"
%TPM_EXE_PATH%pcrextend -ha 0 -halg sha1 -ic policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policypcr0.txt has 20 * 00

REM # create AND term for policy PCR
REM # > policymakerpcr -halg sha1 -bm 10000 -if policypcr0.txt -v -pr -of policypcr.txt

REM # convert to binary policy
REM # > policymaker -halg sha1 -if policypcr.txt -of policypcr.bin -pr -v

echo ""
echo "Policy PCR"
echo ""

echo "Create a signing key with policy PCR PCR 16 zero"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -nalg sha1 -pol policies/policypcr.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reset PCR 16 back to zero"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read PCR 16, should be 00 00 00 00 ..."
%TPM_EXE_PATH%pcrread -ha 16 -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, policy not satisfied - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 85 33 11 83"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should succeed"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR extend PCR 16"
%TPM_EXE_PATH%pcrextend -ha 16 -halg sha1 -ic policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read PCR 0, should be 1d 47 f6 8a ..."
%TPM_EXE_PATH%pcrread -ha 16 -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the wrong digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 66 dd e5 e3"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # 01000000 authorizing ndex
REM # 01000001 authorized index
REM # 03000000 policy session
REM #
REM # 4 byte NV index
REM # policynv.txt
REM # policy CC_PolicyNV || args || Name
REM #
REM # policynvargs.txt (binary)
REM # args = hash of 0000 0000 0000 0000 | 0000 | 0000 (eight bytes of zero | offset | op ==)
REM # hash -hi n -halg sha1 -if policynvargs.txt -v
REM # openssl dgst -sha1 policynvargs.txt
REM # 2c513f149e737ec4063fc1d37aee9beabc4b4bbf
REM #
REM # NV authorizing index
REM #
REM # after defining index and NV write to set written, use 
REM # nvreadpublic -ha 01000000 -nalg sha1
REM # to get name
REM # 00042234b8df7cdf8605ee0a2088ac7dfe34c6566c5c
REM #
REM # append Name to policynvnv.txt
REM #
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policynvnv.txt -of policynvnv.bin -pr -v
REM # bc 9b 4c 4f 7b 00 66 19 5b 1d d9 9c 92 7e ad 57 e7 1c 2a fc 
REM #
REM # file zero8.bin has 8 bytes of hex zero

echo ""
echo "Policy NV, NV index authorizing"
echo ""

echo "Define a setbits index, authorizing index"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -ty b > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV setbits to set written"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read, should be zero"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define an ordinary index, authorized index, policyNV"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000001 -pwdn nnn -sz 2 -ty o -pol policies/policynvnv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000001 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write to set written"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -ic aa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "NV write, policy not satisfied  - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy get digest, should be 0"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV to satisfy the policy"
%TPM_EXE_PATH%policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be bc 9b 4c 4f ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied"
%TPM_EXE_PATH%nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set bit in authorizing NV index"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -pwdn nnn -bit 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read, should be 1"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV to satisfy the policy - should fail"
%TPM_EXE_PATH%policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy get digest, should be 00 00 00 00 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorizing index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorized index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy NV Written"
echo ""

echo "Define an ordinary index, authorized index, policyNV"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -sz 2 -ty o -pol policies/policywrittenset.bin > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "NV write, policy not satisfied  - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy NV Written no, does not satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws n > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy not satisfied - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied but written clear - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write using password, set written"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written no"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws n > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes - should fail"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorizing index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # test using clockrateadjust
REM # policycphashhash.txt is (hex) 00000130 4000000c 000
REM # hash -if policycphashhash.txt -oh policycphashhash.bin -halg sha1 -v
REM # openssl dgst -sha1 policycphashhash.txt
REM # cpHash is
REM # b5f919bbc01f0ebad02010169a67a8c158ec12f3
REM # append to policycphash.txt 00000163 + cpHash
REM # policymaker -halg sha1 -if policycphash.txt -of policycphash.bin -pr
REM #  06 e4 6c f9 f3 c7 0f 30 10 18 7c a6 72 69 b0 84 b4 52 11 6f 

echo ""
echo "Policy cpHash"
echo ""

echo "Set the platform policy to policy cpHash"
%TPM_EXE_PATH%setprimarypolicy -hi p -pol policies/policycphash.bin -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust using wrong password - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0  > run.out 
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy not satisfied - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy cpHash, satisfy policy"
%TPM_EXE_PATH%policycphash -ha 03000000 -cp policies/policycphashhash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "Policy get digest, should be 06 e4 6c f9"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied but bad command params - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 1 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear the platform policy"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # test using clockrateadjust and platform policy

REM # operand A time is 64 bits at offset 0, operation GT (2)
REM # policycountertimerargs.txt (binary)
REM # args = hash of operandB | offset | operation
REM # 0000 0000 0000 0000 | 0000 | 0002
REM # hash -hi n -halg sha1 -if policycountertimerargs.txt -v
REM # openssl dgst -sha1 policycountertimerargs.txt
REM # 7a5836fe287e11ac39ee88d3c0794916d50b73c3
REM # 
REM # policycountertimer.txt 
REM # policy CC_PolicyCounterTimer || args
REM # 0000016d + args
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policycountertimer.txt -of policycountertimer.bin -pr -v
REM # e6 84 81 27 55 c0 39 d3 68 63 21 c8 93 50 25 dd aa 26 42 9a 

echo ""
echo "Policy Counter Timer"
echo ""

echo "Set the platform policy to policy "
%TPM_EXE_PATH%setprimarypolicy -hi p -pol policies/policycountertimer.bin -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust using wrong password - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy not satisfied - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy counter timer, zero operandB, op EQ satisfy policy - should fail"
%TPM_EXE_PATH%policycountertimer -ha 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)
 
echo "Policy counter timer, zero operandB, op GT satisfy policy"
%TPM_EXE_PATH%policycountertimer -ha 03000000 -if policies/zero8.bin -op 2 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "Policy get digest, should be e6 84 81 27"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied"
%TPM_EXE_PATH%clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear the platform policy"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policyccsign.txt  0000016c 0000015d (policy command code | sign)
REM # policyccquote.txt 0000016c 00000158 (policy command code | quote)
REM #
REM # > policymaker -if policyccsign.txt -of policyccsign.bin -pr -v
REM # cc6918b226273b08f5bd406d7f10cf160f0a7d13dfd83b7770ccbcd1aa80d811
REM #
REM # > policymaker -if policyccquote.txt -of policyccquote.bin -pr -v
REM # a039cad5fe68870688f8233c3e3ee3cf27aac9e2efe3486aeb4e304c0e90cd27
REM #
REM # policyor.txt is CC_PolicyOR || digests
REM # 00000171 | cc69 ... | a039 ...
REM # > policymaker -if policyor.txt -of policyor.bin -pr -v
REM # 6b fe c2 3a be 57 b0 2a ce 39 dd 13 bb 60 fa 39 
REM # 4d ac 7b 38 96 56 57 84 b3 73 fc 61 92 94 29 db 

echo ""
echo "PolicyOR"
echo ""

echo "Create an unrestricted signing key, policy command code sign or quote"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp pps -pwdk sig -pol policies/policyor.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Quote - should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Get time - should fail, policy not set"
%TPM_EXE_PATH%gettime -hk 80000001 -qd policies/aaa -se1 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy OR - should fail"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000015d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be cc 69 18 b2"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be 6b fe c2 3a"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign with policy OR"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000015d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - should fail, wrong command code"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - quote, digest a0 39 ca d5"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 00000158 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR, digest 6b fe c2 3a"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote with policy OR"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - gettime 7a 3e bd aa"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000014c > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR, gettime not an AND term - should fail"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm tmppol.bin
rm tmppriv.bin
rm tmppub.bin
exit /B 0

REM # getcapability -cap 1 -pr 80000000
REM # getcapability -cap 1 -pr 01000000
REM # getcapability -cap 1 -pr 02000000
REM # getcapability -cap 1 -pr 03000000
