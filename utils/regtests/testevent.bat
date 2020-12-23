REM #############################################################################
REM #									        #
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2020                                        #
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
echo "UEFI"
echo ""

for %%M in ("-sim" "-tpm" ) do (

    echo "UEFI %%M dell 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if dell1.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M hp 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if hp1.log > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M ideapad 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if ideapad1.log > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M deb 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if deb1.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M deb 2"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if deb2.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M p51 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if p511.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M sm 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if sm1.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M sm 2"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if sm2.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M ubuntu 1"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if ubuntu1.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "UEFI %%M ubuntu 2"
    %TPM_EXE_PATH%eventextend -checkhash -v %%M -if ubuntu2.log > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "IMA"
echo ""

for %%M in (" " "-sim" ) do (
    echo "IMA %%~M Test Log"
    %TPM_EXE_PATH%imaextend -if imatest.log %%~M -v -le > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
)

REM # cleanup
