@echo off

REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2020					#
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

set soc=
set mssim=
if "%TPM_INTERFACE_TYPE%" == "" (
   set soc=1
)
if "%TPM_INTERFACE_TYPE%" == "socsim" (
   set soc=1
)
if defined soc (
   if "%TPM_SERVER_TYPE%" == "" (
       set mssim=1
   )
   if "%TPM_SERVER_TYPE%" == "mssim" (
      set mssim=1
   )
)

set ITERATE_ALGS=sha1 sha256 sha384 sha512
set BAD_ITERATE_ALGS=sha256 sha384 sha512 sha1

if defined mssim (
   call regtests\inittpm.bat
   IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed inittpm.bat"
      exit /B 1
   )
)

for /f %%i in ('%TPM_EXE_PATH%getrandom -by 16 -ns') do set TPM_SESSION_ENCKEY=%%i
echo "Session state encryption key"
echo %TPM_SESSION_ENCKEY%

call regtests\initkeys.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed initkeys.bat"
   exit /B 1
)

call regtests\testrng.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testrng.bat"
   exit /B 1
)

call regtests\testpcr.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testpcr.bat"
   exit /B 1
)

call regtests\testprimary.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testprimary.bat"
   exit /B 1
)

call regtests\testcreateloaded.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testcreateloaded.bat"
   exit /B 1
)

call regtests\testhmacsession.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testhmacsession.bat"
   exit /B 1
)

call regtests\testbind.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testbind.bat"
   exit /B 1
)

call regtests\testsalt.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testsalt.bat"
   exit /B 1
)

call regtests\testhierarchy.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testhierarchy.bat"
   exit /B 1
)

call regtests\teststorage.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed teststorage.bat"
  exit /B 1
)

call regtests\testchangeauth.bat
   IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testchangeauth.bat"
   exit /B 1
)

call regtests\testencsession.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed testencsession.bat"
  exit /B 1
)

call regtests\testsign.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testsign.bat"
   exit /B 1
)

call regtests\testnv.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed testnv.bat"
  exit /B 1
)

call regtests\testnvpin.bat
 IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testnvpin.bat"
   exit /B 1
 )

call regtests\testevict.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed testevict.bat"
  exit /B 1
)

call regtests\testrsa.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testrsa.bat"
   exit /B 1
)

call regtests\testaes.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testaes.bat"
   exit /B 1
)

call regtests\testaes138.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testaes138.bat"
   exit /B 1
)

call regtests\testhmac.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed testhmac.bat"
  exit /B 1
)

call regtests\testattest.bat
IF !ERRORLEVEL! NEQ 0 (
  echo ""
  echo "Failed testattest.bat"
  exit /B 1
)

call regtests\testpolicy.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testpolicy.bat"
   exit /B 1
)

call regtests\testpolicy138.bat
IF !ERRORLEVEL! NEQ 0 (
   echo ""
   echo "Failed testpolicy138.bat"
   exit /B 1
)

call regtests\testcontext.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testcontext.bat"
  exit /B 1
)

call regtests\testclocks.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testclocks.bat"
  exit /B 1
)

call regtests\testda.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testda.bat"
  exit /B 1
)

call regtests\testunseal.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testunseal.bat"
  exit /B 1
)

call regtests\testdup.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testdup.bat"
  exit /B 1
)

call regtests\testecc.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testecc.bat"
  exit /B 1
)

call regtests\testcredential.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testcredential.bat"
  exit /B 1
)

call regtests\testattest155.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testattest155.bat"
  exit /B 1
)

call regtests\testx509.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testx509.bat"
  exit /B 1
)

call regtests\testgetcap.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testgetcap.bat"
  exit /B 1
)

call regtests\testshutdown.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testshutdown.bat"
  exit /B 1
)

call regtests\testchangeseed.bat
IF !ERRORLEVEL! NEQ 0 (
      echo ""
      echo "Failed testchangeseed.bat"
  exit /B 1
)

REM cleanup

%TPM_EXE_PATH%flushcontext -ha 80000000

rm -f run.out
rm -f despriv.bin
rm -f despub.bin
rm -f prich.bin
rm -f pritk.bin

for %%H in (%ITERATE_ALGS%) do (
	rm -f khpriv%%H.bin
	rm -f khpub%%H.bin
	rm -f khrpriv%%H.bin
	rm -f khrpub%%H.bin
)

for %%B in (2048 3072) do (
	rm -f signrsa%%Bpriv.bin
	rm -f signrsa%%Bpub.bin
	rm -f signrsa%%Bpub.pem
	rm -f derrsa%%Bpriv.bin
	rm -f derrsa%%Bpub.bin
	rm -f signrsa%%Brpriv.bin
	rm -f signrsa%%Brpub.bin
	rm -f signrsa%%Brpub.pem
	rm -f signrsa%%Bnfpriv.bin
	rm -f signrsa%%Bnfpub.bin
	rm -f signrsa%%Bnfpub.pem
	rm -r storersa%%Bpriv.bin
	rm -r storersa%%Bpub.bin
	rm -f storersa%%Bch.bin
	rm -f storersa%%Btk.bin)

for %%C in (nistp256 nistp384) do (
	rm -f storeecc%%Cpriv.bin
	rm -f storeecc%%Cpub.bin

	rm -f signecc%%Cpriv.bin
	rm -f signecc%%Cpub.bin
	rm -f signecc%%Cpub.pem

	rm -f signecc%%Crpriv.bin
	rm -f signecc%%Crpub.bin
	rm -f signecc%%Crpub.pem

	rm -f signecc%%Cnfpriv.bin
	rm -f signecc%%Cnfpub.bin
	rm -f signecc%%Cnfpub.pem

	rm -f tmpkeypairecc%%C.pem
	rm -f tmpkeypairecc%%C.der
)

rm -f stotk.bin
rm -f dec.bin
rm -f derpriv.bin
rm -f enc.bin
rm -f msg.bin
rm -f noncetpm.bin
rm -f policyapproved.bin
rm -f pssig.bin
rm -f sig.bin
rm -f tmp.bin
rm -f tmp1.bin
rm -f tmp2.bin
rm -f tmpsha1.bin
rm -f tmpsha256.bin
rm -f tmpsha384.bin
rm -f tmpsha512.bin
rm -f tmppriv.bin
rm -f tmppub.bin
rm -f tmpspriv.bin
rm -f tmpspub.bin
rm -f to.bin
rm -f zero.bin

echo ""
echo "Success"

exit /B 0
