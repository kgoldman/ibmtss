REM #############################################################################
REM										#
REM			TPM2 regression test					#
REM			     Written by Ken Goldman				#
REM		       IBM Thomas J. Watson Research Center			#
REM		$Id: testpcr.bat 1157 2018-04-17 14:09:56Z kgoldman $		#
REM										#
REM (c) Copyright IBM Corporation 2015, 2017					#
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

echo ""
echo "PCR Extend"
echo ""

for %%H in (sha1 sha256 sha384) do (

    echo "PCR Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "PCR Extend %%H"
    %TPM_EXE_PATH%pcrextend -ha 16 -halg %%H -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "PCR Read %%H"
    %TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "Verify the read data %%H"
    diff policies/%%Hextaaa0.bin tmp.bin
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "PCR Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )
)

echo ""
echo "PCR Event"
echo ""

echo "PCR Reset"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "PCR Read"
%TPM_EXE_PATH%pcrread -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "PCR Event"
%TPM_EXE_PATH%pcrevent -ha 16 -if policies/aaa -of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

for %%H in (sha1 sha256 sha384) do (

    echo "Verify Digest %%H"
    diff policies/%%Haaa.bin tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "PCR Read %%H"
    %TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "Verify Digest %%H"
    diff policies/%%Hexthaaa.bin tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

)

echo ""
echo "Event Sequence Complete"
echo ""

echo "PCR Reset"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Event sequence start, alg null"
%TPM_EXE_PATH%hashsequencestart -halg null -pwda aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Event Sequence Complete"
%TPM_EXE_PATH%eventsequencecomplete -hs 80000001 -pwds aaa -ha 16 -if policies/aaa -of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

for %%H in (sha1 sha256 sha384) do (

    echo "Verify Digest %%H"
    diff policies/%%Haaa.bin tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )
 
    echo "PCR Read %%H"
    %TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "Verify Digest %%H"
    diff policies/%%Hexthaaa.bin tmp%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

)

echo "PCR Reset"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

exit /B 0
