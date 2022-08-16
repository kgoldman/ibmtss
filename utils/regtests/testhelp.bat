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
echo "Usage Help and sessions"
echo ""

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
       exit /B 1
 )

echo "changeeps"
%TPM_EXE_PATH%changeeps -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 0 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 1 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 2 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 3 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 4 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 5 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 6 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 7 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 8 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap 9 -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -cap a -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettestresult"
%TPM_EXE_PATH%gettestresult -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "powerup"
%TPM_EXE_PATH%powerup -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "shutdown"
%TPM_EXE_PATH%shutdown -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "stirrandom"
%TPM_EXE_PATH%stirrandom -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "stirrandom"
%TPM_EXE_PATH%stirrandom -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -v -xxxxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se0 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se0 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se1 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se1 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se2 02000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -se2 02000000 100 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo ""
echo "Usage Help for local utilities"
echo ""

echo "getcryptolibrary"
%TPM_EXE_PATH%getcryptolibrary -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -v -h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo ""
echo "Missing arguments"
echo ""

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -icred > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -ocred > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -is > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -ha > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ActivateCredential"
%TPM_EXE_PATH%activatecredential -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify - > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -ho > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -halg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -salg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -qd > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -os > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Certify"
%TPM_EXE_PATH%certify -oa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -ho > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -halg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -salg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -qd > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -tk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -ch > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -os > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -oa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)


echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ho > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -halg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -rsa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ku > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -iob > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -bit > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -sub > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -opc > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -oa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -otbs > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -os > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ocert > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "changepps"
%TPM_EXE_PATH%changepps -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -state > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -adj > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -clock > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -iclock > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -addsec > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -pt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -s2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -y2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -Kf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -Lf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -Ef > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -Cf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "commit"
%TPM_EXE_PATH%commit -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "contextload"
%TPM_EXE_PATH%contextload -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -rsa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -bl > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -kt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -opr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -opem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -ch > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -root > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -cakey > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -capwd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -caalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -rsa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -bl > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -opr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -opem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -pwdpi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -iu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -opem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -ch > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -bl > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -kt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -pwd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -pwd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -nmt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -nrt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -lr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -ho > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -ik > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -oek > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -oss > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -ipwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -ic1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -ic2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -ic3 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -oc1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -oc2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -oc3 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -cv > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -ecc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -oq > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -cf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -pcrmax > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -pwds > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -of1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -of2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -of3 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -of5 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -ho > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -cap > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -pr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -pc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcapability"
%TPM_EXE_PATH%getcapability -pc 0 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -qd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -oa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -by > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -qd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -oa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -qd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -oa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -oh > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hashsequencestart"
%TPM_EXE_PATH%hashsequencestart -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwdni > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwdai > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -he > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -state > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -ty > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -b > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -e > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -l > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -ik > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -iss > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -opr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -ipem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -scheme > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -opr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -ipr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -pwdk  > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ider > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -scheme > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -icred > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -in > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -ocred > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -sz > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -off > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -oa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -sz > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -ty > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace +at > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -pwd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvincrement"
%TPM_EXE_PATH%nvincrement -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -sz > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -ocert > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -off > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -on > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -pdwn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -bit > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -off > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -hia > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -ho > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -ipwdn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -opr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -of1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -of2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -of3 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -of5 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread - ha> run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -ahalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -iosad > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "pcrreset"
%TPM_EXE_PATH%pcrreset -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -appr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -pref > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -skn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -cc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ic > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -off > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -op > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -cp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -inpn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -ion > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -io > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -nh > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv - > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -ws > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -bm > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -in > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -cp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -pref > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -exp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -pwde > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -to > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -in > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -cp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -pref > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -exp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -sk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -is > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -te > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -to > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -cp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -pref > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -na > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -invpu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ipem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ider > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -on > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -nalg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -hp > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -qd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -palg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -otime > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -oclock > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -ho > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -opu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic -opem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -ho > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -pwdo > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -hn > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -in > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -iss > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -oss > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -ipwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -ie > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -od > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -oid > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -id > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -oe > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -pwds > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -pwds > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -set > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setcommandcodeauditstatus"
%TPM_EXE_PATH%setcommandcodeauditstatus -clr > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -hi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -pol > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "setprimarypolicy"
%TPM_EXE_PATH%setprimarypolicy -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -salg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -scheme > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -cf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -os > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -hs > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -bi > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -pwdb > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -sym > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -on > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -loc > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "stirrandom"
%TPM_EXE_PATH%stirrandom -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -opem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -ipu > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -pt > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -ha > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -pwd > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal -of > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -if > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -ih > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -is > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -ipem > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -ihmac > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -tk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -halg > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -hk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -qsb > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -qeb > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -cf > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -scheme > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -z1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -z2 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo ""
echo "policycommandcode"
echo ""

for %%C in (11f 120 121 122 124 125 126 127 128 129 12a 12b 12c 12d 12e 130 131 132 133 134 135 136 137 138 139 13a 13b 13c 13d 13e 13f 140 142 143 144 145 146 147 148 149 14a 14b 14c 14d 14e 14f 150 151 152 153 154 155 156 157 158 159 15b 15c 15d 15e 160 161 162 163 164 165 167 168 169 16a 16b 16c 16d 16e 16f 170 171 172 173 174 176 177 178 17a 17b 17c 17d 17e 17f 180 181 182 183 184 185 186 187 188 189 18a 18b 18c 18d 18e 18f 190 191 192 193 197 199 19A) do (

    echo "startauthsession"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "policycommandcode"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -v -cc %%C > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )


    echo "Flush the session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "Missing Parameter"
echo ""

echo "activatecredential"
%TPM_EXE_PATH%activatecredential > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "activatecredential"
%TPM_EXE_PATH%activatecredential -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "activatecredential"
%TPM_EXE_PATH%activatecredential -ha 1 -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "activatecredential"
%TPM_EXE_PATH%activatecredential  -ha 1 -hk 1 -icred xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -ho 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certify"
%TPM_EXE_PATH%certify -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -ho 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -ho 1 -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifycreation"
%TPM_EXE_PATH%certifycreation -ho 1 -hk 1 -tk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ho 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ho 1 -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "certifyx509"
%TPM_EXE_PATH%certifyx509 -ho 1 -hk 1 -rsa 2048 -ecc nistp256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "changeeps"
%TPM_EXE_PATH%changeeps -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset 1"
%TPM_EXE_PATH%dictionaryattacklockreset > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -pwda xxx -hi p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset 2"
%TPM_EXE_PATH%dictionaryattacklockreset > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "clear"
%TPM_EXE_PATH%clear -pwda xxx -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -pwda xxx -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clearcontrol"
%TPM_EXE_PATH%clearcontrol -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "clockrateadjust"
%TPM_EXE_PATH%clockrateadjust -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -iclock xxx -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -clock 123 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -clock 123 -iclock xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "clockset"
%TPM_EXE_PATH%clockset -clock 123 -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "contextsave"
%TPM_EXE_PATH%contextsave -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -gp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -116 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -kt nf > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -kt np > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -kt ed > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -kt xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp 1 -kt p -kt p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp 1 -bl > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp 1 -dau > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp 1 -dar > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "create"
%TPM_EXE_PATH%create -hp 1 -gp -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa 2048 -high > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa 4096 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -ecc nistp521 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -te -no > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa 2048 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createek"
%TPM_EXE_PATH%createek -rsa 2048 -ecc nistp256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -noflush > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 2048 -high > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 4096 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -ecc nistp521 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -caalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 2048 -cakey cakey.pem -vv > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 2048 -ecc nistp256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -rsa 2048 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createekcert"
%TPM_EXE_PATH%createekcert -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -deo > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -des > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -sir > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hkr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -dp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -gp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -116 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt nf > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt np > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt ed > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -uwa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -halg sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -halg sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -halg sha384 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -nalg sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -nalg sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -nalg sha384 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hp 1 -pol > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hp 1 -bl > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -hp 1 -st -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createloaded"
%TPM_EXE_PATH%createloaded -kt xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -den"
%TPM_EXE_PATH%createprimary -den -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -gp"
%TPM_EXE_PATH%createprimary -gp -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -116"
%TPM_EXE_PATH%createprimary -116 -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -ecc xxx"
%TPM_EXE_PATH%createprimary -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -kt ed "
%TPM_EXE_PATH%createprimary -kt ed > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -kt xxx"
%TPM_EXE_PATH%createprimary -kt xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -uwa"
%TPM_EXE_PATH%createprimary -uwa -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -da"
%TPM_EXE_PATH%createprimary -da -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -halg xxx"
%TPM_EXE_PATH%createprimary -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -nalg xxx"
%TPM_EXE_PATH%createprimary -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -pwdk"
%TPM_EXE_PATH%createprimary -pwdk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -dar"
%TPM_EXE_PATH%createprimary -dar > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary -ecc nistp256"
%TPM_EXE_PATH%createprimary -ecc nistp256 -daa -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -pwdp xxx -pwdpi xxx  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "createprimary"
%TPM_EXE_PATH%createprimary -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "dictionaryattacklockreset"
%TPM_EXE_PATH%dictionaryattacklockreset -pwd "" > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "dictionaryattackparameters"
%TPM_EXE_PATH%dictionaryattackparameters -lr 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -oek xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -ho 1 -ik xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "duplicate"
%TPM_EXE_PATH%duplicate -ho 1 -salg aes > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -ipwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccdecrypt"
%TPM_EXE_PATH%eccdecrypt -hk 1 -ic1 xxx -ic2 xxx -ic3 xxx -pwdk xxx -ipwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -halg xxx  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccencrypt"
%TPM_EXE_PATH%eccencrypt -hk 1  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -cv xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters -of xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eccparameters"
%TPM_EXE_PATH%eccparameters > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ecephemeral"
%TPM_EXE_PATH%ecephemeral -ecc xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "encryptdecrypt"
%TPM_EXE_PATH%encryptdecrypt -hk 1 -if encryptdecrypt.c > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -nospec > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -ns > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -pcrmax 8 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -if xxx -nospec -sim > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventextend"
%TPM_EXE_PATH%eventextend -if xxx -nospec > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "eventsequencecomplete"
%TPM_EXE_PATH%eventsequencecomplete -hs 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -ho 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -ho 1 -hp 1 -hi o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "evictcontrol"
%TPM_EXE_PATH%evictcontrol -ho 1 -hp 1 -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "flushcontext"
%TPM_EXE_PATH%flushcontext -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -pwde xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getcommandauditdigest"
%TPM_EXE_PATH%getcommandauditdigest -halg sha256 -salg rsa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getrandom"
%TPM_EXE_PATH%getrandom -by 100000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -pwde xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "getsessionauditdigest"
%TPM_EXE_PATH%getsessionauditdigest -hs 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -pwde xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "gettime"
%TPM_EXE_PATH%gettime > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash -ns > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash"
%TPM_EXE_PATH%hash > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash -if xxx -ic xxx"
%TPM_EXE_PATH%hash -if xxx -ic xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash -hi e -ic xxx"
%TPM_EXE_PATH%hash -hi e -ic xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)


echo "hash -hi o -ic xxx"
%TPM_EXE_PATH%hash -hi o -ic xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "hash -hi xxx -ic xxx"
%TPM_EXE_PATH%hash -hi xxx -ic xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hash- if encryptdecrypt.c"
%TPM_EXE_PATH%hash -if encryptdecrypt.c > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -hi x> run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwdn x -pwdni x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchychangeauth"
%TPM_EXE_PATH%hierarchychangeauth -pwda x -pwdai x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -hi e  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -hi o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -he e  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -he o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hierarchycontrol"
%TPM_EXE_PATH%hierarchycontrol -he x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -hk 1 -ic 1 -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmac"
%TPM_EXE_PATH%hmac -hk 1 -if encryptdecrypt.c > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "hmacstart"
%TPM_EXE_PATH%hmacstart > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend -ty 3"
%TPM_EXE_PATH%imaextend -ty 3 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend -b 0"
%TPM_EXE_PATH%imaextend -b 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend -e 0"
%TPM_EXE_PATH%imaextend -e 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -l 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "imaextend"
%TPM_EXE_PATH%imaextend -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -salg xxx"
%TPM_EXE_PATH%import -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -salg aes"
%TPM_EXE_PATH%import -salg aes > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 "
%TPM_EXE_PATH%import -ik 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 -ipu xxx -id xxx"
%TPM_EXE_PATH%import -ik 1 -ipu xxx -id xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 -ipu xxx -id xxx"
%TPM_EXE_PATH%import -salg aes -ik 1 -ipu xxx -id xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 -ipu xxx -id xxx"
%TPM_EXE_PATH%import -hp 1 -salg aes -ik 1 -ipu xxx -id xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 -ipu xxx -id xxx"
%TPM_EXE_PATH%import -hp 1 -salg aes -ik 1 -ipu xxx -iss xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -ik 1 -ipu xxx -id xxx -iss xxx"
%TPM_EXE_PATH%import -ik 1 -ipu xxx -id xxx -iss xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import -salg aes -ik 1 -ipu xxx -id xxx -iss xxx"
%TPM_EXE_PATH%import -hp 1 -salg aes -ik 1 -ipu xxx -id xxx -iss xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "import"
%TPM_EXE_PATH%import -hp 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -si -scheme rsapss > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -st -scheme rsapss > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -scheme rsapss > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -scheme xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -hp 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -hp 1 -ipem xxx -si -st > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem -hp 1 -ipem xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "importpem"
%TPM_EXE_PATH%importpem  -hp 1 -ipem xxx -opu xxx> run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -hp 1> run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load -hp 1 -ipr xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "load"
%TPM_EXE_PATH%load > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -scheme xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -st -scheme rsassa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -si -st > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -hi o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -hi e > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -hi n > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "loadexternal"
%TPM_EXE_PATH%loadexternal -ipem xxx -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential -ha 1 -icred xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "makecredential"
%TPM_EXE_PATH%makecredential > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify missing -kh"
%TPM_EXE_PATH%nvcertify > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify -hia > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
nvcertify -hk 1 -ha 01000000 -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvcertify"
%TPM_EXE_PATH%nvcertify > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvchangeauth"
%TPM_EXE_PATH%nvchangeauth > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace +at xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at ow > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at or > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at pw > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at pr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace"
%TPM_EXE_PATH%nvdefinespace -at xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace -ty o -ty c "
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -ty o -ty c > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace -hia xxx"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hia xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace -hi xxx"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace -ty x"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi p -ty x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvdefinespace policy mismatch"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hia p -hi p -pol policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -ha 20000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -ha 01000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvextend"
%TPM_EXE_PATH%nvextend -ha 01000000 -ic xxx -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvglobalwritelock"
%TPM_EXE_PATH%nvglobalwritelock -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -of > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -sz 70000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread  -ha 01000000 -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -id > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -id 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvread"
%TPM_EXE_PATH%nvread -ha 01000000 -id 1 1 -sz 4 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadlock"
%TPM_EXE_PATH%nvreadlock -ha 01000000 -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvreadpublic"
%TPM_EXE_PATH%nvreadpublic > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -pwdn > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvsetbits"
%TPM_EXE_PATH%nvsetbits -bit 65 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -ha 30000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespace"
%TPM_EXE_PATH%nvundefinespace -ha 01000000 -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -pwdp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvundefinespacespecial"
%TPM_EXE_PATH%nvundefinespacespecial -ha 30000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -id > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -id 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -ha 30000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -ha 01000000 -if xxx -ic xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwrite"
%TPM_EXE_PATH%nvwrite -ha 01000000 -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -ha 30000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "nvwritelock"
%TPM_EXE_PATH%nvwritelock -ha 01000000 -hia x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -hp 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -hp 1 -ho 1 -pwdn xxx -ipwdn xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "objectchangeauth"
%TPM_EXE_PATH%objectchangeauth -hp 1 -ho 1 -pwdn "" > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate -pwdp xxx "
%TPM_EXE_PATH%pcrallocate -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate +sha1 +sha1 "
%TPM_EXE_PATH%pcrallocate -pwdp xxx +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate -sha1 -sha1"
%TPM_EXE_PATH%pcrallocate -pwdp xxx -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate sha256 +sha256 "
%TPM_EXE_PATH%pcrallocate -pwdp xxx +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate -sha256 -sha256"
%TPM_EXE_PATH%pcrallocate -pwdp xxx -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate +sha384 +sha384"
%TPM_EXE_PATH%pcrallocate -pwdp xxx +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate -sha384 -sha384"
%TPM_EXE_PATH%pcrallocate -pwdp xxx -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate +sha512 +sha512"
%TPM_EXE_PATH%pcrallocate -pwdp xxx +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate -sha512 -sha512"
%TPM_EXE_PATH%pcrallocate -pwdp xxx -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate"
%TPM_EXE_PATH%pcrallocate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrallocate sha1 -pwdp xxx"
%TPM_EXE_PATH%pcrallocate +sha1 -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent -ha 0 -ic x"
%TPM_EXE_PATH%pcrevent -ha 0 -ic x > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -ha 24 -ic x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -ha 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrevent"
%TPM_EXE_PATH%pcrevent -ha 0 -ic x -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 24 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 0 -ic x -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 0 -ic 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678990123456789901234567899012345678990123456789  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 0 -if policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrextend"
%TPM_EXE_PATH%pcrextend -ha 0 -ic x -v > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "pcrread -ha"
%TPM_EXE_PATH%pcrread -ha > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread" -ha 0 -halg sha1 -halg sha256
%TPM_EXE_PATH%pcrread -ha 0 -halg sha1 -halg sha256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "pcrread ha 0 -halg sha1 -halg sha1"
%TPM_EXE_PATH%pcrread -ha 0 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread -ha 0 -halg xxx"
%TPM_EXE_PATH%pcrread -ha 0 -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread -ha 0 -ahalg xxx"
%TPM_EXE_PATH%pcrread -ha 0 -ahalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -ha 0 -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrread -ha 24 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrreset -ha 24 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "pcrread"
%TPM_EXE_PATH%pcrreset -ha 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -pref > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -ha 1 -appr xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -ha 1 -appr xxx -skn xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorize"
%TPM_EXE_PATH%policyauthorize -ha 1 -appr policies/sha1aaa.bin -skn xxx -tk xxx -pref policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthorizenv"
%TPM_EXE_PATH%policyauthorizenv -ha 1 -hs 1 -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyauthvalue"
%TPM_EXE_PATH%policyauthvalue -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycommandcode"
%TPM_EXE_PATH%policycommandcode -ha 02000000 -cc 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ic > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ha 1 -if policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycountertimer"
%TPM_EXE_PATH%policycountertimer -ha 1 -ic 1111 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policycphash"
%TPM_EXE_PATH%policycphash -ha 1 -cp policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -ha 1 -inpn 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyduplicationselect"
%TPM_EXE_PATH%policyduplicationselect -ha 1 -inpn 1 -ion policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policygetdigest"
%TPM_EXE_PATH%policygetdigest -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker -if xxx"
%TPM_EXE_PATH%policymaker -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker -halg sha1"
%TPM_EXE_PATH%policymaker -halg sha1 -if policies/policysignedsha1.txt -of tmp.bin -pr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "policymaker -halg sha256"
%TPM_EXE_PATH%policymaker -halg sha256 -if policies/policysignedsha256.txt -of tmp.bin -nz > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "policymakerr -halg sha384"
%TPM_EXE_PATH%policymaker -halg sha384 -if policies/policysignedsha384.txt -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "policymaker -halg sha512"
%TPM_EXE_PATH%policymaker -halg sha512 -if policies/policysignedsha512.txt -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "policymaker -halg xxx"
%TPM_EXE_PATH%policymaker -halg xxx -if policies/policysignedsha1.txt -of tmp.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -if policies/policycountertimer.txt -of tmp.bin -pr -v > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "policymaker -halg sha1"
%TPM_EXE_PATH%policymaker -halg sha1 -if policies/policysignedsha1.txt -of tmp.bin -pr -of xxx/xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policymaker"
%TPM_EXE_PATH%policymaker -if policies/policysignedsha1.bin -of tmp.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash -ha 1 -nh policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynamehash"
%TPM_EXE_PATH%policynamehash  -ha 1 -nh policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -pwda > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -hs > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ic > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -if > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ic 1111 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -hi > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha 1 -hs 1 -ic x -hi o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha 1 -hs 1 -ic x -hi p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha 1 -hs 1 -ic x -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -off > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -op > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha 1 -hs 1  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynv"
%TPM_EXE_PATH%policynv -ha 1 -hs 1 -ic x -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policynvwritten"
%TPM_EXE_PATH%policynvwritten -hs 1 -ws x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -if x -if x -if x -if x -if x -if x -if x -if x -if x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -if x -if x -if x -if x -if x -if x -if x -if x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyor"
%TPM_EXE_PATH%policyor -ha 1 -if x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypassword"
%TPM_EXE_PATH%policypassword -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -bm q > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -ha > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policypcr"
%TPM_EXE_PATH%policypcr -ha 1 -bm 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyrestart"
%TPM_EXE_PATH%policyrestart -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -cp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -pref > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -ha 1 -hs 1 -cp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysecret"
%TPM_EXE_PATH%policysecret -ha 1 -hs 1 -pref xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -pref > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -tk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -halg > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk 1 -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk 1 -ha 1 -sk 1 -is 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk 1 -ha 1 -sk 1 -pref xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -hk 1 -ha 1 -sk 1 -is xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policysigned"
%TPM_EXE_PATH%policysigned -to > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate -ha 1 -te xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policytemplate"
%TPM_EXE_PATH%policytemplate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -cp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -cp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -pref > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -pref xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to ooo > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to xxx -na nnn > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to xxx -hi h > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk kkk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin -cp policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi e -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi o -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "policyticket"
%TPM_EXE_PATH%policyticket -ha 1 -to policies/sha1aaa.bin -hi h -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -nalg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -si -scheme > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -si -scheme rsassa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -si -scheme rsapss > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -si -scheme null > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -si -scheme xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -st > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -den > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -uwa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ns > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ns > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ipem xxx -ider yyy > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ipem xxx -si -st > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ipu xxx -si -uwa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "publicname"
%TPM_EXE_PATH%publicname -ider ddd -st > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -hp 24 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -hk > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -palg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -oa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "quote"
%TPM_EXE_PATH%quote -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readclock"
%TPM_EXE_PATH%readclock -otime > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "readpublic"
%TPM_EXE_PATH%readpublic > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -ho 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -ho 1 -hn 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -ho 1 -hn 1 id xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rewrap"
%TPM_EXE_PATH%rewrap -ho 1 -hn 1 -id xxx -in xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -oid xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -hk 1 -ie xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsadecrypt"
%TPM_EXE_PATH%rsadecrypt -hk 1 -ie xxx -pwdk xxx -ipwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "rsaencrypt"
%TPM_EXE_PATH%rsaencrypt -hk 1 -id xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hs 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hs 1 -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequencecomplete"
%TPM_EXE_PATH%sequencecomplete -hs 1 -if policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate"
%TPM_EXE_PATH%sequenceupdate > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate -hs 1"
%TPM_EXE_PATH%sequenceupdate -hs 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sequenceupdate -hs 1 -if policies/sha1aaa.bin"
%TPM_EXE_PATH%sequenceupdate -hs 1 -if policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx -set 00000000"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx -set 00000001 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx -halg sha1"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx -halg sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx -halg sha256"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx -halg sha256 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx -halg sha384"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx -halg sha384 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx -halg sha512"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx -halg sha512 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -halg xxx"
%TPM_EXE_PATH%setcommandcodeauditstatus -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -set 00000000 -hi o"
%TPM_EXE_PATH%setcommandcodeauditstatus -set 00000000 -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -set 00000000 -hi x"
%TPM_EXE_PATH%setcommandcodeauditstatus -set 00000000 -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setcommandcodeauditstatus -pwda xxx"
%TPM_EXE_PATH%setcommandcodeauditstatus -pwda xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy -halg sha1"
%TPM_EXE_PATH%setprimarypolicy -halg sha1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy -halg xxx"
%TPM_EXE_PATH%setprimarypolicy -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy -pol policies/sha1aaa.bin"
%TPM_EXE_PATH%setprimarypolicy -pol policies/sha1aaa.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "setprimarypolicy -hi l"
%TPM_EXE_PATH%setprimarypolicy -hi l > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "setprimarypolicy -hi e"
%TPM_EXE_PATH%setprimarypolicy -hi e > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "setprimarypolicy -hi o"
%TPM_EXE_PATH%setprimarypolicy -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "setprimarypolicy -hi x"
%TPM_EXE_PATH%setprimarypolicy -hi x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -salg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -scheme eca > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -scheme xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -kh 1 -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "sign"
%TPM_EXE_PATH%sign -kh 1 -if xxx -scheme ecdaa > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "signapp"
%TPM_EXE_PATH%signapp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "signapp"
%TPM_EXE_PATH%signapp -ic > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "signapp"
%TPM_EXE_PATH%signapp -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "signapp"
%TPM_EXE_PATH%signapp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "signapp"
%TPM_EXE_PATH%signapp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -halg xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -sym xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -pwdb xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startauthsession"
%TPM_EXE_PATH%startauthsession -se x > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup -loc 7 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "startup"
%TPM_EXE_PATH%startup > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "stirrandom"
%TPM_EXE_PATH%stirrandom > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "stirrandom"
%TPM_EXE_PATH%stirrandom -if encryptdecrypt.c > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -ipu xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem -ipu xxx -opem xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpm2pem"
%TPM_EXE_PATH%tpm2pem > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -ipu xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmpublic2eccpoint"
%TPM_EXE_PATH%tpmpublic2eccpoint -ipu  signrsa2048nfpub.bin -pt policies/tmp.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "unseal"
%TPM_EXE_PATH%unseal > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -halg xxx  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -ih xxx t > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature -hk 1 -if xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "verifysignature"
%TPM_EXE_PATH%verifysignature > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "writeapp"
%TPM_EXE_PATH%writeapp -xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -scheme xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -hk 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -hk 1 -qsb xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -hk 1 -qsb xxx -qeb xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -z1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -z2 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "zgen2phase"
%TPM_EXE_PATH%zgen2phase -pwd > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

REM # cleanup

rm -rf tmp.bin

exit /B 0


echo "policymakerpcr"
%TPM_EXE_PATH%policymakerpcr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "printattr"
%TPM_EXE_PATH%printattr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "returncode"
%TPM_EXE_PATH%returncode > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "timepacket"
%TPM_EXE_PATH%timepacket > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "tpmproxy"
%TPM_EXE_PATH%tpmproxy > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)
exit /B 0
