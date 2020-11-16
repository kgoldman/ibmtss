#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2020                                            #
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
echo "UEFI"
echo ""

for MODE in "-sim" "-tpm" 
do

    echo "UEFI ${MODE} dell 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if dell1.log > dell1.txt
    checkSuccess $?

    echo "UEFI ${MODE} hp 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if hp1.log > hp1.txt
    checkSuccess $?

    echo "UEFI ${MODE} ideapad 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ideapad1.log  > ideapad1.txt
    checkSuccess $?

    echo "UEFI ${MODE} deb 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if deb1.log > deb1.txt
    checkSuccess $?

    echo "UEFI ${MODE} deb 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if deb2.log > deb2.txt
    checkSuccess $?

    echo "UEFI ${MODE} p51 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if p511.log > p511.txt
    checkSuccess $?

    echo "UEFI ${MODE} sm 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if sm1.log > sm1.txt
    checkSuccess $?

    echo "UEFI ${MODE} sm 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if sm2.log > sm2.txt
    checkSuccess $?

    echo "UEFI ${MODE} ubuntu 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ubuntu1.log > ubuntu1.txt
    checkSuccess $?

    echo "UEFI ${MODE} ubuntu 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ubuntu2.log > ubuntu2.txt
    checkSuccess $?

done

echo ""
echo "IMA"
echo ""

for MODE in "" "-sim" 
do
    echo "IMA ${MODE} Test Log"
    ${PREFIX}imaextend -if imatest.log ${MODE} -v -le > imatest.txt
    checkSuccess $?
done

# cleanup

rm -f deb1.txt
rm -f deb2.txt
rm -f dell1.txt
rm -f hp1.txt
rm -f ideapad1.txt
rm -f p511.txt
rm -f sm1.txt
rm -f sm2.txt
rm -f ubuntu1.txt
rm -f ubuntu2.txt
rm -f imatest.txt
