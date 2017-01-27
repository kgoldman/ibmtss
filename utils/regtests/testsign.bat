REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testsign.bat 914 2017-01-16 22:05:26Z kgoldman $		#
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

echo ""
echo "RSA Signing key"
echo ""

REM # loop over unrestricted hash algorithms

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signpriv.bin -ipu signpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a key pair in PEM format using openssl"
  
openssl genrsa -out tmpkeypair.pem -aes256 -passout pass:rrrr 2048 > run.out

echo "Convert key pair to plaintext DER format"

openssl rsa -inform pem -outform der -in tmpkeypair.pem -out tmpkeypair.der -passin pass:rrrr > run.out

for %%H in (sha1 sha256) do (

    echo "Sign a digest - %%H"
    %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -if policies/aaa -os sig.bin -pwdk sig -ipu signpub.bin -ipem signpub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the signature - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if policies/aaa -is sig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Load the openssl key pair in the NULL hierarchy - %%H"
    %TPM_EXE_PATH%loadexternal -halg %%H -ider tmpkeypair.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Use the TPM as a crypto coprocessor to sign - %%H" 
    %TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the signature - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000002 -halg %%H -if policies/aaa -is sig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the openssl signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "ECC Signing key"
echo ""

echo "Load the ECC signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%H in (sha1 sha256) do (

    echo "Sign a digest - %%H"
    %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -ecc -if policies/aaa -os sig.bin -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the ECC signature - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -ecc -if policies/aaa -is sig.bin  > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)


echo "Flush the ECC signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

echo ""
echo "Primary Signing Key"
echo ""

REM # primary signing key 80000001

for %%H in (sha1 sha256) do (
    
    echo "Create primary signing key - RSA, %%H"
    %TPM_EXE_PATH%createprimary -si -opu tmppub.bin -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Sign a digest - %%H"
    %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -if policies/aaa -os sig.bin -pwdk sig -ipu tmppub.bin -ipem tmppub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the signature - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if policies/aaa -is sig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the primary signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)


echo "Create primary signing key - ECC"
%TPM_EXE_PATH%createprimary -si -opu tmppub.bin -ecc nistp256 -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - SHA1"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha1 -ecc -if policies/aaa -os sig.bin -pwdk sig > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create primary signing key - restricted"
%TPM_EXE_PATH%createprimary -sir -opu tmppub.bin -pwdk sig  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - SHA256 - should fail TPM_RC_TICKET"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256  -if policies/aaa -os sig.bin  -pwdk sig -ipu tmppub.bin -ipem signpub.pem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "External Verification Key"
echo ""

REM # create rsaprivkey.pem
REM # > openssl genrsa -out rsaprivkey.pem -aes256 -passout pass:rrrr 2048
REM # extract the public key
REM # > openssl pkey -inform pem -outform pem -in rsaprivkey.pem -passin pass:rrrr -pubout -out rsapubkey.pem 
REM # sign a test message msg.bin
REM # > openssl dgst -sha1 -sign rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin

echo "Load external just the public part of PEM RSA"
%TPM_EXE_PATH%loadexternal -halg sha1 -nalg sha1 -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a test message with openssl RSA"
openssl dgst -sha1 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin

echo "Verify the RSA signature"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha1 -if msg.bin -is pssig.bin -raw > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # generate the p256 key
REM # > openssl ecparam -name prime256v1 -genkey -noout -out p256privkey.pem
REM # extract public key
REM # > openssl pkey -inform pem -outform pem -in p256privkey.pem -pubout -out p256pubkey.pem

echo "Load external just the public part of PEM ECC"
%TPM_EXE_PATH%loadexternal -halg sha1 -nalg sha1 -ipem policies/p256pubkey.pem -ecc > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a test message with openssl ECC"
openssl dgst -sha1 -sign policies/p256privkey.pem -out pssig.bin msg.bin

echo "Verify the ECC signature"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha1 -if msg.bin -is pssig.bin -raw -ecc > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm tmpkeypair.pem
rm tmpkeypair.der
rm signpub.pem
rm pssig.bin
rm -r tmppub.bin
rm -r tmppub.pem

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
