REM #############################################################################
REM										#
REM			TPM2 regression test					#
REM			     Written by Ken Goldman				#
REM		       IBM Thomas J. Watson Research Center			#
REM										#
REM (c) Copyright IBM Corporation 2015 - 2020					#
REM 										#
REM All rights reserved.							#
REM 										#
REM Redistribution and use in source and binary forms, with or without		#
REM modification, are permitted provided that the following conditions are	#
REM met:									#
REM 										#
REM Redistributions of source code must retain the above copyright notice,	#
REM this list of conditions and the following disclaimer.			#
REM 										#
REM Redistributions in binary form must reproduce the above copyright		#
REM notice, this list of conditions and the following disclaimer in the		#
REM documentation and/or other materials provided with the distribution.	#
REM 										#
REM Neither the names of the IBM Corporation nor the names of its		#
REM contributors may be used to endorse or promote products derived from	#
REM this software without specific prior written permission.			#
REM 										#
REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
REM "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
REM LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	#
REM A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT	#
REM HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
REM SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
REM LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	#
REM DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	#
REM THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	#
REM OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.	#
REM										#
REM #############################################################################

setlocal enableDelayedExpansion
 
echo | set /p="1234567890123456" > msg.bin
touch zero.bin

REM try to undefine any NV index left over from a previous test.  Do not check for errors.
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 -pwdp ppp > run.out
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000002 > run.out
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000003 > run.out

REM same for persistent objects
%TPM_EXE_PATH%evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out

echo ""
echo "Initialize Regression Test Keys"
echo ""

echo "Create a platform primary RSA storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -pol policies/zerosha256.bin -tk pritk.bin -ch prich.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

set SHALG=sha256 sha384
set BITS=2048 3072
set CURVE=nistp256 nistp384

set i=0
for %%s in (!SHALG!) do set /A i+=1 & set SHALG[!i!]=%%s
set i=0
for %%b in (!BITS!)  do set /A i+=1 & set BITS[!i!]=%%b
set i=0
for %%c in (!CURVE!) do set /A i+=1 & set CURVE[!i!]=%%c
set L=!i!

for /L %%i in (1,1,!L!) do (

    echo "Create an RSA !BITS[%%i]! !SHALG[%%i]! storage key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -st -kt f -kt p -pol policies/policycccreate-auth.bin -opr storersa!BITS[%%i]!priv.bin -opu storersa!BITS[%%i]!pub.bin -tk storersa!BITS[%%i]!tk.bin -ch storersa!BITS[%%i]!ch.bin -pwdp sto -pwdk sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create an RSA !BITS[%%i]! !SHALG[%%i]! unrestricted signing key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -rsa !BITS[%%i]! -halg !SHALG[%%i]! -si -kt f -kt p -opr signrsa!BITS[%%i]!priv.bin -opu signrsa!BITS[%%i]!pub.bin -opem signrsa!BITS[%%i]!pub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an RSA !BITS[%%i]! decryption key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -den -kt f -kt p -opr derrsa!BITS[%%i]!priv.bin -opu derrsa!BITS[%%i]!pub.bin -pwdp sto -pwdk dec > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an RSA !BITS[%%i]! !SHALG[%%i]! restricted signing key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -rsa !BITS[%%i]! -halg !SHALG[%%i]! -sir -kt f -kt p -opr signrsa!BITS[%%i]!rpriv.bin -opu signrsa!BITS[%%i]!rpub.bin -opem signrsa!BITS[%%i]!rpub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an RSA !BITS[%%i]! !SHALG[%%i]! not fixedTPM signing key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -rsa !BITS[%%i]! -halg !SHALG[%%i]! -sir -opr signrsa!BITS[%%i]!nfpriv.bin -opu signrsa!BITS[%%i]!nfpub.bin -opem signrsa!BITS[%%i]!nfpub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Create an ECC !CURVE[%%i]! !SHALG[%%i]! storage key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -ecc !CURVE[%%i]! -halg !SHALG[%%i]! -st -kt f -kt p -opr storeecc!CURVE[%%i]!priv.bin -opu storeecc!CURVE[%%i]!pub.bin -pwdp sto -pwdk sto > run.out
     IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an ECC !CURVE[%%i]! !SHALG[%%i]! unrestricted signing key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -ecc !CURVE[%%i]! -halg !SHALG[%%i]! -si -kt f -kt p -opr signecc!CURVE[%%i]!priv.bin -opu signecc!CURVE[%%i]!pub.bin -opem signecc!CURVE[%%i]!pub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an ECC !CURVE[%%i]! !SHALG[%%i]! restricted signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc !CURVE[%%i]! -halg !SHALG[%%i]! -sir -kt f -kt p -opr signecc!CURVE[%%i]!rpriv.bin -opu signecc!CURVE[%%i]!rpub.bin -opem signecc!CURVE[%%i]!rpub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an ECC !CURVE[%%i]! !SHALG[%%i]! not fixedTPM signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc !CURVE[%%i]! -halg !SHALG[%%i]! -sir -opr signecc%%Cnfpriv.bin -opu signecc%%Cnfpub.bin -opem signecc%%Cnfpub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

)

echo "Create a symmetric cipher key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -des -kt f -kt p -opr despriv.bin -opu despub.bin -pwdp sto -pwdk aes > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

for %%H in (%ITERATE_ALGS%) do (

    echo "Create a %%H unrestricted keyed hash key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -kh -kt f -kt p -opr khpriv%%H.bin -opu khpub%%H.bin -pwdp sto -pwdk khk -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a %%H restricted keyed hash key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -khr -kt f -kt p -opr khrpriv%%H.bin -opu khrpub%%H.bin -pwdp sto -pwdk khk -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

exit /B 0


