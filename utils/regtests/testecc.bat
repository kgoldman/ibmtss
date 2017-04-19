REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testecc.bat 988 2017-04-17 19:21:25Z kgoldman $		#
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
echo "EC CEphemeral"
echo ""

echo ""
echo "ECC Parameters and Ephemeral"
echo ""

for %%C in (bnp256 nistp256 nistp384) do (

    echo "ECC Parameters for curve %%C"
    %TPM_EXE_PATH%eccparameters -cv %%C > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    for %%A in (-si -sir) do (

	echo "Create %%A for curve %%C"
	%TPM_EXE_PATH%create -hp 80000000 -pwdp pps %%A -ecc %%C > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

    )

    echo "EC Ephemeral for curve %%C"
    %TPM_EXE_PATH%ecephemeral -ecc %%C > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
)

echo ""
echo "ECC Commit"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for %%K in ("-dau" "-dar") do (

    for %%S in ("" "-se0 02000000 1") do (

	echo "Create a %%~K ECDAA signing key under the primary key"
	%TPM_EXE_PATH%create -hp 80000000 -ecc bnp256 %%~K -nalg sha256 -halg sha256 -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp pps -pwdk siga > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

	echo "Load the signing key 80000001 under the primary key 80000000"
	%TPM_EXE_PATH%load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp pps > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

    	REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000001
    	
    	REM The trick with commit is first use - empty ECC point and no s2 and y2 parameters
    	REM which means no P1, no s2 and no y2. 
    	REM and output the result and get the efile.bin
    	REM feed back the point in efile.bin as the new p1 because it is on the curve.
	
    	REM There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm.
	REM example of normal command    
    	REM %TPM_EXE_PATH%commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -pwdk siga > run.out
	
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point %%~S"
	%TPM_EXE_PATH%commit -hk 80000001 -Ef efile.bin -pwdk siga  %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        REM We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
		
	REM All this does is simulate the commit that the FIDO alliance wants to
	REM use in its TPM Join operation.
		
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point %%~S"
	%TPM_EXE_PATH%commit -hk 80000001 -pt efile.bin -Ef efile.bin -pwdk siga %%~S > run.out
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


for %%K in ("-dau" "-dar") do (
    for %%S in ("" "-se0 02000000 1") do (

        echo "Create a %%~K ECDAA signing primary key"
        %TPM_EXE_PATH%createprimary -ecc bnp256 %%~K -nalg sha256 -halg sha256 -kt f -kt p -opu tmprpub.bin -pwdk siga > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
        REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000001
        
        REM The trick with commit is first use - empty ECC point and no s2 and y2 parameters
        REM which means no P1, no s2 and no y2. 
        REM and output the result and get the efile.bin
        REM feed back the point in efile.bin as the new p1 because it is on the curve.
        
        REM There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm."
        REM example of normal command    
        REM %TPM_EXE_PATH%commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -pwdk siga > run.out
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point %%~S"
        %TPM_EXE_PATH%commit -hk 80000001 -Ef efile.bin -pwdk siga %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
        REM We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
        
        REM All this does is simulate the commit that the FIDO alliance wants to
        REM use in its TPM Join operation.
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point %%~S"
        %TPM_EXE_PATH%commit -hk 80000001 -pt efile.bin -Ef efile.bin -pwdk siga %%~S > run.out
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

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -rf efile.bin
rm -rf tmprpub.bin
rm -rf tmprpriv.bin

REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000
exit /B 0
