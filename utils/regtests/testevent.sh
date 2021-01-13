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

for FILE in "dell1" "hp1" "ideapad1" "deb1" "deb2" "p511" "sm1" "sm2" "ubuntu1" "ubuntu2"
do 
    for MODE in "-sim" "-tpm" 
    do

    echo "UEFI ${MODE} ${FILE} "
    ${PREFIX}eventextend -checkhash -v ${MODE} -if ${FILE}.log > run.out
    checkSuccess $?

    done
done

echo ""
echo "IMA"
echo ""

for TYPE in "1" "2"
do
    for HALG in ${ITERATE_ALGS}
    do

	echo "Power cycle to reset IMA PCR"
	${PREFIX}powerup > run.out
	checkSuccess $?

	echo "Startup"
	${PREFIX}startup > run.out
	checkSuccess $?

	echo "IMA ${HALG} Test Log type ${TYPE} simulate"
	${PREFIX}imaextend -le -if imatest.log -sim -halg ${HALG} -ty ${TYPE}  -checkhash -of tmpsim.bin > run.out
	checkSuccess $?

	echo "IMA ${HALG} Test Log type ${TYPE} extend"
	${PREFIX}imaextend -le -if imatest.log -tpm -halg ${HALG} -ty ${TYPE}  -checkhash > run.out
	checkSuccess $?

	echo "PCR read ${HALG}"
	${PREFIX}pcrread -ha 10 -halg ${HALG} -of tmppcr.bin > run.out
	checkSuccess $?

	echo "Verify PCR vs sim"
	diff tmppcr.bin tmpsim.bin > run.out
	checkSuccess $?

    done
done

# cleanup

rm -f tmptpm.bin
rm -f tmpsim.bin
