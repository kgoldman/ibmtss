REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testattest.bat 593 2016-05-18 15:04:15Z kgoldman $		#
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
echo "Attestation"
echo ""

echo "Load the RSA signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signpriv.bin -ipu signpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the ECC signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Define Space"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read Public, unwritten Name"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if msg.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    for %%H in (sha1 sha256 sha384) do (

    	for %%A in (rsa ecc) do (

		IF "%%A" == "rsa" (
		   set K=80000001
		)
		IF "%%A" == "ecc" (
		   set K=80000002
		)		

		echo "Signing Key Self Certify %%H %%A %%~S"
		%TPM_EXE_PATH%certify -hk !K! -ho 80000001 -halg %%H -pwdk sig -pwdo sig %%~S -os sig.bin -oa tmp.bin -qd policies/aaa -salg %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Verify the %%A signature %%H"
		%TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Quote %%H %%A %%~S"
		%TPM_EXE_PATH%quote -hp 0 -hk !K! -halg %%H -palg %%H -pwdk sig %%~S -os sig.bin -oa tmp.bin -qd policies/aaa -salg %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Verify the %%A signature %%H"
		%TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Get Time %%H %%A %%~S"
		%TPM_EXE_PATH%gettime -hk !K! -halg %%H -pwdk sig %%~S -os sig.bin -oa tmp.bin -qd policies/aaa -salg %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Verify the %%A signature %%H"
		%TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "NV Certify %%H %%A %%~S"
		%TPM_EXE_PATH%nvcertify -ha 01000000 -pwdn nnn -hk !K! -pwdk sig -halg %%H -sz 16 %%~S -os sig.bin -oa tmp.bin -salg %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Verify the %%A signature %%H"
		%TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Get command audit digest %%H %%A %%~S"
		%TPM_EXE_PATH%getcommandauditdigest -hk !K! -halg %%H %%~S -pwdk sig -os sig.bin -oa tmp.bin -qd policies/aaa -salg %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	
		echo "Verify the %%A signature"
		%TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
		IF !ERRORLEVEL! NEQ 0 (
		exit /B 1
		)
	)
    )
)

echo "Flush the RSA attestation key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the ECC attestation key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Audit"
echo ""

REM 80000001 signing key
REM 02000000 hmac and audit session

echo ""
echo "Audit with one session"
echo ""

echo "Load the audit signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signpriv.bin -ipu signpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%B in ("" "-bi 80000001 -pwdb sig") do (

    for %%H in (sha1 sha256 sha384) do (
    

    echo "Start an HMAC auth session %%H %%~B"
    %TPM_EXE_PATH%startauthsession -se h -halg %%H %%~B > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Sign a digest %%H"
    %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -if policies/aaa -os sig.bin -pwdk sig -ipu signpub.bin -se0 02000000 81 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Sign a digest %%H"
    %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -if policies/aaa -os sig.bin -pwdk sig -se0 02000000 81 -ipu signpub.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get Session Audit Digest %%H"
    %TPM_EXE_PATH%getsessionauditdigest -hs 02000000 -hk 80000001 -pwdk sig -halg %%H -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the signature %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if tmp.bin -is sig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the session"
    %TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    )
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM 80000001 signing key
REM 02000000 hmac session
REM 02000001 audit session

echo ""
echo "Audit with HMAC and audit sessions"
echo ""

echo "Load the audit signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signpriv.bin -ipu signpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    for %%H in (sha1 sha256 sha384) do (

       echo "Start an audit session %%H"
       %TPM_EXE_PATH%startauthsession -se h -halg %%H > run.out
       IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
       )
    
       echo "Sign a digest %%H"
       %TPM_EXE_PATH%sign -hk 80000001 -halg %%H -if policies/aaa -os sig.bin -pwdk sig -ipu signpub.bin -se0 02000001 81 > run.out
       IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
       )
    
       echo "Get Session Audit Digest %%~S"
       %TPM_EXE_PATH%getsessionauditdigest -hs 02000001 -hk 80000001 -pwdk sig -os sig.bin -oa tmp.bin %%~S -qd policies/aaa > run.out
       IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
       )
    
       echo "Verify the signature"
       %TPM_EXE_PATH%verifysignature -hk 80000001 -if tmp.bin -is sig.bin > run.out
       IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
       )
    
       echo "Flush the session"
       %TPM_EXE_PATH%flushcontext -ha 02000001 > run.out
       IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
       )
    
    )
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

exit /B 0

REM getcapability -cap 1 -pr 80000000
REM getcapability -cap 1 -pr 02000000
