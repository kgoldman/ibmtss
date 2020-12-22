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
    ${PREFIX}eventextend -checkhash -v ${MODE} -if dell1.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} hp 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if hp1.log > run.out 
    checkSuccess $?

    echo "UEFI ${MODE} ideapad 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ideapad1.log > run.out 
    checkSuccess $?

    echo "UEFI ${MODE} deb 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if deb1.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} deb 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if deb2.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} p51 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if p511.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} sm 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if sm1.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} sm 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if sm2.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} ubuntu 1"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ubuntu1.log > run.out
    checkSuccess $?

    echo "UEFI ${MODE} ubuntu 2"
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ubuntu2.log > run.out
    checkSuccess $?

done

echo ""
echo "IMA"
echo ""

for MODE in "" "-sim" 
do
    echo "IMA ${MODE} Test Log"
    ${PREFIX}imaextend -if imatest.log ${MODE} -v -le > run.out
    checkSuccess $?
done

# cleanup
