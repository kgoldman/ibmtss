REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: teststorage.bat 943 2017-02-22 15:03:11Z kgoldman $	#
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

REM Primary storage key at 80000000 password pps
REM storage key at 80000001 password sto

echo ""
echo "Storage key"
echo ""

echo "Load the storage key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr storepriv.bin -ipu storepub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%N in (sha1 sha256 sha384) do (

    for %%S in ("" "-se0 02000000 1") do (

        echo "Create an unrestricted signing key under the storage key %%N %%~S"
        %TPM_EXE_PATH%create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 111 -nalg %%N %%~S > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Load the signing key under the storage key %%~S"
        %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto %%~S > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
	echo "Read the signing key public area"
	%TPM_EXE_PATH%readpublic -ho 80000002 -opu tmppub2.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )

        echo "Flush the signing key"
        %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Load external just the storage key public part %%N"
        %TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu storepub.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Flush the public key"
        %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
	echo "Load external, signing key public part %%N"
	%TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu tmppub2.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )

	echo "Flush the public key"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
     )
)

echo "Flush the storage key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "ECC Storage key"
echo ""

echo "Create a ECC primary storage key 80000001"
%TPM_EXE_PATH%createprimary -ecc nistp256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a ECC storage key under the ECC primary storage key 80000001"
%TPM_EXE_PATH%create -hp 80000001 -ecc nistp256 -st -opr tmppriv.bin -opu tmppub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the ECC storage key 80000002 under the ECC primary key 80000001"
%TPM_EXE_PATH%load -hp 80000001 -ipu tmppub.bin -ipr tmppriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the ECC primary storage key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the ECC storage key 80000002"
%TPM_EXE_PATH%create -hp 80000002 -ecc nistp256 -si -opr tmppriv.bin -opu tmppub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the ECC storage key 80000001 under the ECC storage key 80000002"
%TPM_EXE_PATH%load -hp 80000002 -ipu tmppub.bin -ipr tmppriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest woith ECC signing key 80000001"
%TPM_EXE_PATH%sign -hk 80000001 -ecc -if policies/sha256aaa.bin -os tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature using the ECC signing key 80000001"
%TPM_EXE_PATH%verifysignature -hk 80000001 -ecc -if policies/sha256aaa.bin -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmppub2.bin
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpsig.bin

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
