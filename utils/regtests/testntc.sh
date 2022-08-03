#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2022					        #
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
echo "Nuvoton Commands"
echo ""

# help

echo "Preconfig Help"
${PREFIX}ntc2preconfig -v -h > run.out
checkFailure $?

echo "Preconfig"
${PREFIX}ntc2preconfig -v > run.out
checkFailure $?

echo "Get Config Help"
${PREFIX}ntc2getconfig -v -h > run.out
checkFailure $?

# unknown paramater

echo "Get Config"
${PREFIX}ntc2getconfig -xxx > run.out
checkFailure $?

echo "Pre Config"
${PREFIX}ntc2preconfig -xxx > run.out
checkFailure $?

# missing override value parameter

for OV in \
	-i2cLoc1_2	\
	-i2cLoc3_4	\
	-AltCfg		\
	-Direction	\
	-PullUp		\
	-PushPull	\
	-CFG_A		\
	-CFG_B		\
	-CFG_C		\
	-CFG_D		\
	-CFG_E		\
	-CFG_F		\
	-CFG_G		\
	-CFG_H		\
	-CFG_I		\
	-CFG_J		\
	-IsValid 
do

    echo "ntc2preconfig override ${OV}"
    ${PREFIX}ntc2preconfig -override ${OV} > run.out
    checkFailure $?

done

# P8 verify

echo "Preconfig P8"
${PREFIX}ntc2preconfig -p8 > run.out
checkSuccess $?

echo "Get Config P8"
${PREFIX}ntc2getconfig -verify -p8 > run.out
checkSuccess $?

echo "Get Config P9, should fail"
${PREFIX}ntc2getconfig -verify -p9 > run.out
checkFailure $?

# P8 override fails verification

for OV in \
    "-i2cLoc1_2	1f" \
	"-i2cLoc3_4	1f" \
	"-AltCfg	13" \
	"-CFG_A		1e" \
	"-CFG_B		1f" \
	"-CFG_C		1f" \
	"-CFG_D		1f" \
	"-CFG_E		1f" \
	"-CFG_G		1f" \
	"-CFG_H		1f"
do

    echo "Preconfig P8"
    ${PREFIX}ntc2preconfig -p8 > run.out
    checkSuccess $?

    echo "Preconfig P8 override ${OV}"
    ${PREFIX}ntc2preconfig -override ${OV} > run.out
    checkSuccess $?

    echo "Get Config P8"
    ${PREFIX}ntc2getconfig -verify -p8 > run.out
    checkFailure $?

done

# P9 verify

echo "Preconfig P9"
${PREFIX}ntc2preconfig -p9 > run.out
checkSuccess $?

echo "Get Config P9"
${PREFIX}ntc2getconfig -verify -p9 > run.out
checkSuccess $?

echo "Get Config P8, should fail"
${PREFIX}ntc2getconfig -verify -p8 > run.out
checkFailure $?

# P9 override fails verification

for OV in \
    "-i2cLoc1_2	1f" \
	"-i2cLoc3_4	1f" \
	"-AltCfg	13" \
	"-CFG_A		1e" \
	"-CFG_B		1f" \
	"-CFG_C		1f" \
	"-CFG_D		1f" \
	"-CFG_E		1f" \
	"-CFG_G		1f" \
	"-CFG_H		1f"
do

    echo "Preconfig P9"
    ${PREFIX}ntc2preconfig -p9 > run.out
    checkSuccess $?

    echo "Preconfig P9 override ${OV}"
    ${PREFIX}ntc2preconfig -override ${OV} > run.out
    checkSuccess $?

    echo "Get Config P9, should fail"
    ${PREFIX}ntc2getconfig -verify -p9 > run.out
    checkFailure $?

done

# values that cannot be changed, success

for OV in \
    "-Direction     00" \
    "-PullUp        ff"
do

    echo "Preconfig P9"
    ${PREFIX}ntc2preconfig -p9 > run.out
    checkSuccess $?

    echo "Preconfig P9 override ${OV}"
    ${PREFIX}ntc2preconfig -override ${OV} > run.out
    checkSuccess $?

    echo "Get Config P9"
    ${PREFIX}ntc2getconfig -verify -p9 > run.out
    checkSuccess $?

done

echo "Get Config Locked"
${PREFIX}ntc2getconfig -verifylocked -p9 > run.out
checkFailure $?

# values that cannot be changed, failure

for OV in \
    "-PushPull" \
    "-CFG_F" \
    "-CFG_I" \
    "-CFG_J" \
    "-IsValid"
do

    echo "Preconfig override ${OV}"
    ${PREFIX}ntc2preconfig -override ${OV} 1 > run.out
    checkFailure $?

done

echo "Preconfig P8 and P9"
${PREFIX}ntc2preconfig -p8 -p9 > run.out
checkFailure $?

echo "Getconfig verify P8 and P9"
${PREFIX}ntc2getconfig -p8 -p9 -verify > run.out
checkFailure $?

echo "Getconfig no P8 or P9"
${PREFIX}ntc2getconfig -verify > run.out
checkFailure $?

echo "Preconfig P8 override"
${PREFIX}ntc2preconfig -p8 -CFG_H 1f > run.out
checkFailure $?

echo "Preconfig P9 override"
${PREFIX}ntc2preconfig -p9 -CFG_H 1f > run.out
checkFailure $?

echo "Preconfig override no parameter"
${PREFIX}ntc2preconfig -override > run.out
checkFailure $?
