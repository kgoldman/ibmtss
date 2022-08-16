REM #################################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2022					#
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
echo "Nuvoton Commands"
echo ""

rem # help

echo "Preconfig Help"
%TPM_EXE_PATH%ntc2preconfig -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Preconfig"
%TPM_EXE_PATH%ntc2preconfig -v > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Get Config Help"
%TPM_EXE_PATH%ntc2getconfig -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

rem # unknown paramater

echo "Get Config"
%TPM_EXE_PATH%ntc2getconfig -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Pre Config"
%TPM_EXE_PATH%ntc2preconfig -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

rem # missing override value parameter

for %%V in (-i2cLoc1_2	-i2cLoc3_4 -AltCfg -Direction -PullUp -PushPull -CFG_A -CFG_B -CFG_C -CFG_D -CFG_E -CFG_F -CFG_G -CFG_H	-CFG_I -CFG_J -IsValid) do (

    echo "ntc2preconfig override %%V"
    %TPM_EXE_PATH%ntc2preconfig -override %%V > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

)

rem # P8 verify

echo "Preconfig P8"
%TPM_EXE_PATH%ntc2preconfig -p8 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Get Config P8"
%TPM_EXE_PATH%ntc2getconfig -verify -p8 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Get Config P9, should fail"
%TPM_EXE_PATH%ntc2getconfig -verify -p9 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

rem # P8 override fails verification

for %%V in ("-i2cLoc1_2	1f" "-i2cLoc3_4	1f" "-AltCfg 13" "-CFG_A 1e" "-CFG_B	1f" "-CFG_C	1f" "-CFG_D	1f" "-CFG_E	1f" "-CFG_G	1f" "-CFG_H	1f") do (

    echo "Preconfig P8"
    %TPM_EXE_PATH%ntc2preconfig -p8 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Preconfig P8 override %%~V"
    %TPM_EXE_PATH%ntc2preconfig -override %%~V > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get Config P8"
    %TPM_EXE_PATH%ntc2getconfig -verify -p8 > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

)

rem # P9 verify

echo "Preconfig P9"
%TPM_EXE_PATH%ntc2preconfig -p9 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Get Config P9"
%TPM_EXE_PATH%ntc2getconfig -verify -p9 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Get Config P8, should fail"
%TPM_EXE_PATH%ntc2getconfig -verify -p8 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

rem # P9 override fails verification

for %%V in ("-i2cLoc1_2	1f" 	"-i2cLoc3_4	1f" 	"-AltCfg	13" 	"-CFG_A		1e" 	"-CFG_B		1f" 	"-CFG_C		1f" 	"-CFG_D		1f" 	"-CFG_E		1f" 	"-CFG_G		1f" 	"-CFG_H		1f") do (

    echo "Preconfig P9"
    %TPM_EXE_PATH%ntc2preconfig -p9 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Preconfig P9 override %%~V"
    %TPM_EXE_PATH%ntc2preconfig -override %%~V > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get Config P9, should fail"
    %TPM_EXE_PATH%ntc2getconfig -verify -p9 > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

)

rem # values that cannot be changed, success

for %%V in ("-Direction     00"     "-PullUp        ff") do (


    echo "Preconfig P9"
    %TPM_EXE_PATH%ntc2preconfig -p9 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Preconfig P9 override %%~V"
    %TPM_EXE_PATH%ntc2preconfig -override %%~V > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get Config P9"
    %TPM_EXE_PATH%ntc2getconfig -verify -p9 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo "Get Config Locked, should fail"
%TPM_EXE_PATH%ntc2getconfig -verifylocked -p9 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

rem # values that cannot be changed, failure

for %%V in ("-PushPull"     "-CFG_F"     "-CFG_I"     "-CFG_J"     "-IsValid") do (

    echo "Preconfig override %%~V"
    %TPM_EXE_PATH%ntc2preconfig -override %%~V 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

)

echo "Preconfig P8 and P9"
%TPM_EXE_PATH%ntc2preconfig -p8 -p9 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Getconfig verify P8 and P9"
%TPM_EXE_PATH%ntc2getconfig -p8 -p9 -verify > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Getconfig no P8 or P9"
%TPM_EXE_PATH%ntc2getconfig -verify > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Preconfig P8 override"
%TPM_EXE_PATH%ntc2preconfig -p8 -CFG_H 1f > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Preconfig P9 override"
%TPM_EXE_PATH%ntc2preconfig -p9 -CFG_H 1f > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Preconfig override no parameter"
%TPM_EXE_PATH%ntc2preconfig -override > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

exit /B 0
