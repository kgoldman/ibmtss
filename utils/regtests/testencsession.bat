REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testencsession.bat 480 2015-12-29 22:41:45Z kgoldman $		#
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
echo "Parameter Encryption"
echo ""

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signpriv.bin -ipu signpub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%M in (xor aes) do (

    for %%N in (xor aes) do (

	for %%P in (xor aes) do (


	    echo "Start an HMAC auth session with %%M encryption"
	    %TPM_EXE_PATH%startauthsession -se h -sym %%M > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Start an HMAC auth session with %%N encryption"
	    %TPM_EXE_PATH%startauthsession -se h -sym %%N > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Start an HMAC auth session with %%P encryption"
	    %TPM_EXE_PATH%startauthsession -se h -sym %%P > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    REM one auth

	    for %%A in (21 41 61) do (

		echo "Signing Key Self Certify, one auth %%A"
		%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin ^
		    -se0 02000000 %%A > run.out
		IF !ERRORLEVEL! NEQ 0 (
		   exit /B 1
		)

	    )

	    REM two auth

	    set TWOAUTH0=01 01 01 01 21 21 41 41 61
	    set TWOAUTH1=01 21 41 61 01 41 01 21 01

	    set i=0
	    for %%a in (!TWOAUTH0!) do set /A i+=1 & set TWOAUTH0[!i!]=%%a
	    set i=0
	    for %%b in (!TWOAUTH1!) do set /A i+=1 & set TWOAUTH1[!i!]=%%b
	    set L=!i!

	    for /L %%i in (1,1,!L!) do (

 		echo "Signing Key Self Certify, two auth !TWOAUTH0[%%i]! !TWOAUTH1[%%i]!"
		%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin ^
		    -se0 02000000 !TWOAUTH0[%%i]! -se1 02000001 !TWOAUTH1[%%i]!  > run.out
		IF !ERRORLEVEL! NEQ 0 (
		   exit /B 1
		)

 	    )

	    REM three auth, first 01

	    set THREEAUTH0=01 01 01 01 01 01 01 01 01
	    set THREEAUTH1=01 01 01 01 21 21 41 41 61
	    set THREEAUTH2=01 21 41 61 01 41 01 21 01

	    set i=0
	    for %%a in (!THREEAUTH0!) do set /A i+=1 & set THREEAUTH0[!i!]=%%a
	    set i=0
	    for %%b in (!THREEAUTH1!) do set /A i+=1 & set THREEAUTH1[!i!]=%%b
	    set i=0
	    for %%c in (!THREEAUTH2!) do set /A i+=1 & set THREEAUTH2[!i!]=%%c
	    set L=!i!

	    for /L %%i in (1,1,!L!) do (

		echo "Signing Key Self Certify, three auth !THREEAUTH0[%%i]! !THREEAUTH1[%%i]! !THREEAUTH2[%%i]!"
		%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin ^
		    -se0 02000000 !THREEAUTH0[%%i]! -se1 02000001 !THREEAUTH1[%%i]! -se1 02000002 !THREEAUTH2[%%i]! > run.out
	        IF !ERRORLEVEL! NEQ 0 (
	   	   exit /B 1
	   	)
	    )

	    REM three auth, first 21 41 61
		
	    set THREEAUTH0=21 21 21 41 41 41 61
	    set THREEAUTH1=01 01 41 01 01 21 01
	    set THREEAUTH2=01 41 01 01 21 01 01

	    set i=0
	    for %%a in (!THREEAUTH0!) do set /A i+=1 & set THREEAUTH0[!i!]=%%a
	    set i=0
	    for %%b in (!THREEAUTH1!) do set /A i+=1 & set THREEAUTH1[!i!]=%%b
	    set i=0
	    for %%c in (!THREEAUTH2!) do set /A i+=1 & set THREEAUTH2[!i!]=%%c
	    set L=!i!

	    for /L %%i in (1,1,!L!) do (

		echo "Signing Key Self Certify, three auth !THREEAUTH0[%%i]! !THREEAUTH1[%%i]! !THREEAUTH2[%%i]!"
		%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin ^
		    -se0 02000000 !THREEAUTH0[%%i]! -se1 02000001 !THREEAUTH1[%%i]! -se1 02000002 !THREEAUTH2[%%i]! > run.out
	        IF !ERRORLEVEL! NEQ 0 (
	   	   exit /B 1
	        )
	    )

	    echo "Flush the sessions"
	    %TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Flush the sessions"
	    %TPM_EXE_PATH%flushcontext -ha 02000001 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Flush the sessions"
	    %TPM_EXE_PATH%flushcontext -ha 02000002 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	)
    )
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
