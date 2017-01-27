REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #	$Id$		#
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
echo "CreateLoaded"
echo ""

echo ""
echo "CreateLoaded Primary Key"
echo ""

for %%H in ("40000001" "4000000c" "4000000b") do (

    echo "CreateLoaded primary key, parent %%~H"
    %TPM_EXE_PATH%createloaded -hp %%~H -st -kt f -kt p -pwdk ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Create a storage key under the primary key"
    %TPM_EXE_PATH%create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the primary storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key - should fail"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "CreateLoaded recreate owner primary key"
    %TPM_EXE_PATH%createloaded -hp %%~H -st -kt f -kt p -pwdk ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the primary storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

)

echo ""
echo "CreateLoaded Child Key"
echo ""

echo "CreateLoaded child key, parent 80000000"
%TPM_EXE_PATH%createloaded -hp 80000000 -st -kt f -kt p -pwdp pps -pwdk ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the child key"
%TPM_EXE_PATH%create -hp 80000001 -si -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the child key"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the child key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "CreateLoaded Derived Key"
echo ""

echo "Create a derivation parent under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -dp -opr tmpdppriv.bin -opu tmpdppub.bin -pwdp pps -pwdk dp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the derivation parent to 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpdppriv.bin -ipu tmpdppub.bin -pwdp pps > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the derivation parent key"
%TPM_EXE_PATH%createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp dp -ecc nistp256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the derivation parent"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpdppriv.bin
rm -f tmpdppub.bin
