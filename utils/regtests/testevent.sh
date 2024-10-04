#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2021 - 2024                                     #
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

echo ""
echo "UEFI, pre-OS"
echo ""

for FILE in "dell1" "hp1" "ideapad1" "deb1" "deb2" "p511" "sm1" "sm2" "ubuntu1" "ubuntu2" "amd635"
do 

    echo "Power cycle to reset PCRs"
    ${PREFIX}powerup > run.out
    checkSuccess $?

    echo "Startup"
    ${PREFIX}startup > run.out
    checkSuccess $?

    echo "UEFI ${FILE} "
    ${PREFIX}eventextend -checkhash -v -tpm -sim -checkpcr -if ${FILE}.log > run.out
    checkSuccess $?

done

echo ""
echo "IMA"
echo ""

for HALG in ${ITERATE_ALGS_WITH_SHA1}
do

    echo "Power cycle to reset IMA PCR"
    ${PREFIX}powerup > run.out
    checkSuccess $?

    echo "Startup"
    ${PREFIX}startup > run.out
    checkSuccess $?

    echo "IMA ${HALG} Test SHA-1 composite log simulate"
    ${PREFIX}imaextend -le -if imatest.log -sim -halg ${HALG} -ealg sha1 -checkhash -checkdata -of tmpsim.bin > run.out
    checkSuccess $?

    echo "IMA ${HALG} Test SHA-1 composite log extend"
    ${PREFIX}imaextend -le -if imatest.log -tpm -halg ${HALG} -ealg sha1 -checkhash -checkdata -v > run.out
    checkSuccess $?

    echo "PCR read ${HALG}"
    ${PREFIX}pcrread -ha 10 -halg ${HALG} -of tmppcr.bin > run.out
    checkSuccess $?

    echo "Verify PCR vs sim"
    diff tmppcr.bin tmpsim.bin > run.out
    checkSuccess $?

done

# This section consumes IMA event logs for supported hash algorithms
# and compares the PCR 10 result to known good PCR values captured
# from a Linux boot against a vTPM

# imakvtpcr10.txt was derived from the vTPM (TPM_INTERFACE_TYPE=dev
# using te below commands. It used the SHA-1 log, but the values are
# tested against all four sample logs.

# > imaextend -le -if sha1.log   -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ealg sha1   -sim >! run.out

# > grep "PCR 10" run.out > imakvtpcr10.txt

for HALG in ${ITERATE_ALGS_WITH_SHA1}
do
    echo "Power cycle to reset IMA PCR"
    ${PREFIX}powerup > run.out
    checkSuccess $?

    echo "Startup"
    ${PREFIX}startup > run.out
    checkSuccess $?

    echo "Consume ${HALG} event log -sim"
    ${PREFIX}imaextend -le -if ${HALG}.log -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ealg ${HALG} -sim > run.out
    checkSuccess $?

    echo "Compare PCR10 to known good value from Linux kernel -sim"
    grep "PCR 10:" run.out > tmp.txt
    diff imakvtpcr10.txt tmp.txt
    checkSuccess $?

    echo "Consume ${HALG} event log -tpm"
    ${PREFIX}imaextend -le -if ${HALG}.log -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ealg ${HALG} -tpm > run.out
    checkSuccess $?

    echo "Compare PCR10 to known good value from Linux kernel -tpm"
    grep "PCR 10:" run.out > tmp.txt
    diff imakvtpcr10.txt tmp.txt
    checkSuccess $?

done

# cleanup

rm -f tmppcr.bin
rm -f tmpsim.bin
rm -f tmp.txt

