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
echo "Usage Help and sessions"
echo ""

echo "ActivateCredential"
${PREFIX}activatecredential -v -h > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -v -xxxxx > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se0 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se0 02000000 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se0 02000000 100 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se1 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se1 02000000 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se1 02000000 100 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se2 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se2 02000000 > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -se2 02000000 100 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -v -h > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -v -xxxxx > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se0 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se0 02000000 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se0 02000000 100 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se1 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se1 02000000 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se1 02000000 100 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se2 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se2 02000000 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -se2 02000000 100 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -v -h > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -v -xxxxx > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se0 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se0 02000000 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se0 02000000 100 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se1 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se1 02000000 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se1 02000000 100 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se2 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se2 02000000 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -se2 02000000 100 > run.out
checkFailure $?

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo "certifyx509"
    ${PREFIX}certifyx509 -v -h > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -v -xxxxx > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se0 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se0 02000000 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se0 02000000 100 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se1 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se1 02000000 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se1 02000000 100 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se2 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se2 02000000 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -se2 02000000 100 > run.out
    checkFailure $?

fi

echo "changeeps"
${PREFIX}changeeps -v -h > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -v -xxxxx > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se0 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se0 02000000 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se0 02000000 100 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se1 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se1 02000000 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se1 02000000 100 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se2 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se2 02000000 > run.out
checkFailure $?

echo "changeeps"
${PREFIX}changeeps -se2 02000000 100 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -v -h > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -v -xxxxx > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se0 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se0 02000000 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se0 02000000 100 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se1 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se1 02000000 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se1 02000000 100 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se2 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se2 02000000 > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -se2 02000000 100 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -v -h > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -v -xxxxx > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se0 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se0 02000000 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se0 02000000 100 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se1 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se1 02000000 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se1 02000000 100 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se2 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se2 02000000 > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -se2 02000000 100 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -v -h > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -v -xxxxx > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se0 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se0 02000000 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se0 02000000 100 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se1 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se1 02000000 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se1 02000000 100 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se2 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se2 02000000 > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -se2 02000000 100 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -v -h > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -v -xxxxx > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se0 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se0 02000000 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se0 02000000 100 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se1 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se1 02000000 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se1 02000000 100 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se2 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se2 02000000 > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -se2 02000000 100 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -v -h > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -v -xxxxx > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se0 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se0 02000000 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se0 02000000 100 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se1 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se1 02000000 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se1 02000000 100 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se2 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se2 02000000 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -se2 02000000 100 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -v -h > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -v -xxxxx > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se0 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se0 02000000 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se0 02000000 100 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se1 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se1 02000000 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se1 02000000 100 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se2 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se2 02000000 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -se2 02000000 100 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -v -h > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -v -xxxxx > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se0 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se0 02000000 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se0 02000000 100 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se1 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se1 02000000 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se1 02000000 100 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se2 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se2 02000000 > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -se2 02000000 100 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -v -h > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -v -xxxxx > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se0 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se0 02000000 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se0 02000000 100 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se1 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se1 02000000 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se1 02000000 100 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se2 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se2 02000000 > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -se2 02000000 100 > run.out
checkFailure $?

echo "create"
${PREFIX}create -v -h > run.out
checkFailure $?

echo "create"
${PREFIX}create -v -xxxxx > run.out
checkFailure $?

echo "create"
${PREFIX}create -se0 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se0 02000000 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se0 02000000 100 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se1 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se1 02000000 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se1 02000000 100 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se2 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se2 02000000 > run.out
checkFailure $?

echo "create"
${PREFIX}create -se2 02000000 100 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -v -h > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -v -xxxxx > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se0 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se0 02000000 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se0 02000000 100 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se1 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se1 02000000 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se1 02000000 100 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se2 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se2 02000000 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -se2 02000000 100 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -v -h > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -v -xxxxx > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se0 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se0 02000000 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se0 02000000 100 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se1 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se1 02000000 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se1 02000000 100 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se2 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se2 02000000 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -se2 02000000 100 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -v -h > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -v -xxxxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se0 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se0 02000000 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se0 02000000 100 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se1 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se1 02000000 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se1 02000000 100 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se2 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se2 02000000 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -se2 02000000 100 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -v -h > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -v -xxxxx > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se0 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se0 02000000 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se0 02000000 100 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se1 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se1 02000000 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se1 02000000 100 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se2 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se2 02000000 > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -se2 02000000 100 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -v -h > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -v -xxxxx > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se0 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se0 02000000 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se0 02000000 100 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se1 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se1 02000000 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se1 02000000 100 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se2 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se2 02000000 > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -se2 02000000 100 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -v -h > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -v -xxxxx > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se0 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se0 02000000 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se0 02000000 100 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se1 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se1 02000000 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se1 02000000 100 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se2 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se2 02000000 > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -se2 02000000 100 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -v -h > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -v -xxxxx > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se0 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se0 02000000 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se0 02000000 100 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se1 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se1 02000000 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se1 02000000 100 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se2 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se2 02000000 > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -se2 02000000 100 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -v -h > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -v -xxxxx > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se0 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se0 02000000 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se0 02000000 100 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se1 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se1 02000000 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se1 02000000 100 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se2 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se2 02000000 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -se2 02000000 100 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -v -h > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -v -xxxxx > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se0 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se0 02000000 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se0 02000000 100 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se1 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se1 02000000 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se1 02000000 100 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se2 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se2 02000000 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -se2 02000000 100 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -v -h > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -v -xxxxx > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se0 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se0 02000000 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se0 02000000 100 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se1 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se1 02000000 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se1 02000000 100 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se2 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se2 02000000 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -se2 02000000 100 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -v -h > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -v -xxxxx > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se0 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se0 02000000 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se0 02000000 100 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se1 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se1 02000000 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se1 02000000 100 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se2 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se2 02000000 > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -se2 02000000 100 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -v -h > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -v -xxxxx > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se0 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se0 02000000 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se0 02000000 100 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se1 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se1 02000000 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se1 02000000 100 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se2 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se2 02000000 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -se2 02000000 100 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -v -h > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -v -xxxxx > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se0 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se0 02000000 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se0 02000000 100 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se1 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se1 02000000 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se1 02000000 100 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se2 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se2 02000000 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -se2 02000000 100 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -v -h > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -v -xxxxx > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se0 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se0 02000000 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se0 02000000 100 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se1 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se1 02000000 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se1 02000000 100 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se2 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se2 02000000 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -se2 02000000 100 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -v -h > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -v -xxxxx > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se0 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se0 02000000 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se0 02000000 100 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se1 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se1 02000000 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se1 02000000 100 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se2 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se2 02000000 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -se2 02000000 100 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -v -h > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -v -xxxxx > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se0 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se0 02000000 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se0 02000000 100 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se1 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se1 02000000 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se1 02000000 100 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se2 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se2 02000000 > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -se2 02000000 100 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 0 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 1 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 2 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 3 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 4 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 5 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 6 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 7 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 8 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap 9 -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -cap a -h > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -v -xxxxx > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se0 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se0 02000000 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se0 02000000 100 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se1 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se1 02000000 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se1 02000000 100 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se2 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se2 02000000 > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -se2 02000000 100 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -v -h > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -v -xxxxx > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se0 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se0 02000000 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se0 02000000 100 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se1 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se1 02000000 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se1 02000000 100 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se2 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se2 02000000 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -se2 02000000 100 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -v -h > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -v -xxxxx > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se0 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se0 02000000 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se0 02000000 100 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se1 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se1 02000000 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se1 02000000 100 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se2 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se2 02000000 > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -se2 02000000 100 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -v -h > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -v -xxxxx > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se0 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se0 02000000 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se0 02000000 100 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se1 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se1 02000000 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se1 02000000 100 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se2 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se2 02000000 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -se2 02000000 100 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -v -h > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -v -xxxxx > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se0 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se0 02000000 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se0 02000000 100 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se1 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se1 02000000 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se1 02000000 100 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se2 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se2 02000000 > run.out
checkFailure $?

echo "gettestresult"
${PREFIX}gettestresult -se2 02000000 100 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -v -h > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -v -xxxxx > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se0 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se0 02000000 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se0 02000000 100 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se1 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se1 02000000 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se1 02000000 100 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se2 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se2 02000000 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -se2 02000000 100 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -v -h > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -v -xxxxx > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se0 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se0 02000000 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se0 02000000 100 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se1 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se1 02000000 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se1 02000000 100 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se2 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se2 02000000 > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -se2 02000000 100 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -v -h > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -v -xxxxx > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se0 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se0 02000000 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se0 02000000 100 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se1 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se1 02000000 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se1 02000000 100 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se2 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se2 02000000 > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -se2 02000000 100 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -v -h > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -v -xxxxx > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se0 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se0 02000000 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se0 02000000 100 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se1 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se1 02000000 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se1 02000000 100 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se2 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se2 02000000 > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -se2 02000000 100 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -v -h > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -v -xxxxx > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se0 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se0 02000000 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se0 02000000 100 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se1 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se1 02000000 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se1 02000000 100 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se2 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se2 02000000 > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -se2 02000000 100 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -v -h > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -v -xxxxx > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se0 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se0 02000000 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se0 02000000 100 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se1 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se1 02000000 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se1 02000000 100 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se2 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se2 02000000 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -se2 02000000 100 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -v -h > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -v -xxxxx > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se0 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se0 02000000 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se0 02000000 100 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se1 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se1 02000000 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se1 02000000 100 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se2 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se2 02000000 > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -se2 02000000 100 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -v -h > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -v -xxxxx > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se0 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se0 02000000 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se0 02000000 100 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se1 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se1 02000000 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se1 02000000 100 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se2 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se2 02000000 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -se2 02000000 100 > run.out
checkFailure $?

echo "import"
${PREFIX}import -v -h > run.out
checkFailure $?

echo "import"
${PREFIX}import -v -xxxxx > run.out
checkFailure $?

echo "import"
${PREFIX}import -se0 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se0 02000000 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se0 02000000 100 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se1 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se1 02000000 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se1 02000000 100 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se2 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se2 02000000 > run.out
checkFailure $?

echo "import"
${PREFIX}import -se2 02000000 100 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -v -h > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -v -xxxxx > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se0 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se0 02000000 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se0 02000000 100 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se1 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se1 02000000 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se1 02000000 100 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se2 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se2 02000000 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -se2 02000000 100 > run.out
checkFailure $?

echo "load"
${PREFIX}load -v -h > run.out
checkFailure $?

echo "load"
${PREFIX}load -v -xxxxx > run.out
checkFailure $?

echo "load"
${PREFIX}load -se0 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se0 02000000 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se0 02000000 100 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se1 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se1 02000000 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se1 02000000 100 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se2 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se2 02000000 > run.out
checkFailure $?

echo "load"
${PREFIX}load -se2 02000000 100 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -v -h > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -v -xxxxx > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se0 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se0 02000000 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se0 02000000 100 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se1 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se1 02000000 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se1 02000000 100 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se2 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se2 02000000 > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -se2 02000000 100 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -v -h > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -v -xxxxx > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se0 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se0 02000000 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se0 02000000 100 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se1 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se1 02000000 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se1 02000000 100 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se2 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se2 02000000 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -se2 02000000 100 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -v -h > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -v -xxxxx > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se0 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se0 02000000 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se0 02000000 100 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se1 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se1 02000000 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se1 02000000 100 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se2 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se2 02000000 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -se2 02000000 100 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -v -h > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -v -xxxxx > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se0 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se0 02000000 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se0 02000000 100 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se1 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se1 02000000 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se1 02000000 100 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se2 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se2 02000000 > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -se2 02000000 100 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -v -h > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -v -xxxxx > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se0 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se0 02000000 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se0 02000000 100 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se1 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se1 02000000 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se1 02000000 100 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se2 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se2 02000000 > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -se2 02000000 100 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -v -h > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -v -xxxxx > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se0 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se0 02000000 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se0 02000000 100 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se1 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se1 02000000 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se1 02000000 100 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se2 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se2 02000000 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -se2 02000000 100 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -v -h > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -v -xxxxx > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se0 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se0 02000000 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se0 02000000 100 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se1 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se1 02000000 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se1 02000000 100 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se2 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se2 02000000 > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -se2 02000000 100 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -v -h > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -v -xxxxx > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se0 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se0 02000000 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se0 02000000 100 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se1 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se1 02000000 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se1 02000000 100 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se2 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se2 02000000 > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -se2 02000000 100 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -v -h > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -v -xxxxx > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se0 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se0 02000000 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se0 02000000 100 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se1 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se1 02000000 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se1 02000000 100 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se2 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se2 02000000 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -se2 02000000 100 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -v -h > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -v -xxxxx > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se0 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se0 02000000 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se0 02000000 100 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se1 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se1 02000000 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se1 02000000 100 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se2 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se2 02000000 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -se2 02000000 100 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -v -h > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -v -xxxxx > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se0 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se0 02000000 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se0 02000000 100 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se1 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se1 02000000 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se1 02000000 100 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se2 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se2 02000000 > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -se2 02000000 100 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -v -h > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -v -xxxxx > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se0 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se0 02000000 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se0 02000000 100 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se1 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se1 02000000 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se1 02000000 100 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se2 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se2 02000000 > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -se2 02000000 100 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -v -h > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -v -xxxxx > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se0 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se0 02000000 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se0 02000000 100 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se1 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se1 02000000 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se1 02000000 100 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se2 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se2 02000000 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -se2 02000000 100 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -v -h > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -v -xxxxx > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se0 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se0 02000000 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se0 02000000 100 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se1 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se1 02000000 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se1 02000000 100 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se2 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se2 02000000 > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -se2 02000000 100 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -v -h > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -v -xxxxx > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se0 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se0 02000000 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se0 02000000 100 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se1 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se1 02000000 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se1 02000000 100 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se2 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se2 02000000 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -se2 02000000 100 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -v -h > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -v -xxxxx > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se0 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se0 02000000 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se0 02000000 100 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se1 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se1 02000000 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se1 02000000 100 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se2 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se2 02000000 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -se2 02000000 100 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -v -h > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -v -xxxxx > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se0 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se0 02000000 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se0 02000000 100 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se1 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se1 02000000 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se1 02000000 100 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se2 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se2 02000000 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -se2 02000000 100 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -v -h > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -v -xxxxx > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se0 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se0 02000000 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se0 02000000 100 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se1 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se1 02000000 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se1 02000000 100 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se2 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se2 02000000 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -se2 02000000 100 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -v -h > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -v -xxxxx > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se0 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se0 02000000 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se0 02000000 100 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se1 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se1 02000000 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se1 02000000 100 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se2 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se2 02000000 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -se2 02000000 100 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -v -h > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -v -xxxxx > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se0 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se0 02000000 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se0 02000000 100 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se1 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se1 02000000 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se1 02000000 100 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se2 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se2 02000000 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -se2 02000000 100 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -v -h > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -v -xxxxx > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se0 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se0 02000000 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se0 02000000 100 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se1 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se1 02000000 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se1 02000000 100 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se2 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se2 02000000 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -se2 02000000 100 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -v -h > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -v -xxxxx > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se0 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se0 02000000 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se0 02000000 100 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se1 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se1 02000000 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se1 02000000 100 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se2 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se2 02000000 > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -se2 02000000 100 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -v -h > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -v -xxxxx > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se0 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se0 02000000 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se0 02000000 100 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se1 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se1 02000000 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se1 02000000 100 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se2 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se2 02000000 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -se2 02000000 100 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -v -h > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -v -xxxxx > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se0 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se0 02000000 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se0 02000000 100 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se1 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se1 02000000 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se1 02000000 100 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se2 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se2 02000000 > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -se2 02000000 100 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -v -h > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -v -xxxxx > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se0 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se0 02000000 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se0 02000000 100 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se1 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se1 02000000 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se1 02000000 100 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se2 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se2 02000000 > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -se2 02000000 100 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -v -h > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -v -xxxxx > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se0 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se0 02000000 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se0 02000000 100 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se1 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se1 02000000 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se1 02000000 100 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se2 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se2 02000000 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -se2 02000000 100 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -v -h > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -v -xxxxx > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se0 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se0 02000000 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se0 02000000 100 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se1 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se1 02000000 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se1 02000000 100 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se2 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se2 02000000 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -se2 02000000 100 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -v -h > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -v -xxxxx > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se0 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se0 02000000 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se0 02000000 100 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se1 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se1 02000000 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se1 02000000 100 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se2 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se2 02000000 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -se2 02000000 100 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -v -h > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -v -xxxxx > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se0 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se0 02000000 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se0 02000000 100 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se1 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se1 02000000 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se1 02000000 100 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se2 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se2 02000000 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -se2 02000000 100 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -v -h > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -v -xxxxx > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se0 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se0 02000000 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se0 02000000 100 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se1 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se1 02000000 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se1 02000000 100 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se2 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se2 02000000 > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -se2 02000000 100 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -v -h > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -v -xxxxx > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se0 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se0 02000000 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se0 02000000 100 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se1 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se1 02000000 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se1 02000000 100 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se2 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se2 02000000 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -se2 02000000 100 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -v -h > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -v -xxxxx > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se0 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se0 02000000 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se0 02000000 100 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se1 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se1 02000000 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se1 02000000 100 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se2 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se2 02000000 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -se2 02000000 100 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -v -h > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -v -xxxxx > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se0 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se0 02000000 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se0 02000000 100 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se1 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se1 02000000 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se1 02000000 100 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se2 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se2 02000000 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -se2 02000000 100 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -v -h > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -v -xxxxx > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se0 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se0 02000000 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se0 02000000 100 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se1 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se1 02000000 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se1 02000000 100 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se2 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se2 02000000 > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -se2 02000000 100 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -v -h > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -v -xxxxx > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se0 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se0 02000000 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se0 02000000 100 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se1 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se1 02000000 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se1 02000000 100 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se2 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se2 02000000 > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -se2 02000000 100 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -v -h > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -v -xxxxx > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se0 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se0 02000000 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se0 02000000 100 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se1 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se1 02000000 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se1 02000000 100 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se2 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se2 02000000 > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -se2 02000000 100 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -v -h > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -v -xxxxx > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se0 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se0 02000000 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se0 02000000 100 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se1 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se1 02000000 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se1 02000000 100 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se2 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se2 02000000 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -se2 02000000 100 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -v -h > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -v -xxxxx > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se0 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se0 02000000 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se0 02000000 100 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se1 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se1 02000000 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se1 02000000 100 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se2 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se2 02000000 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -se2 02000000 100 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -v -h > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -v -xxxxx > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se0 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se0 02000000 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se0 02000000 100 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se1 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se1 02000000 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se1 02000000 100 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se2 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se2 02000000 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -se2 02000000 100 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -v -h > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -v -xxxxx > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se0 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se0 02000000 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se0 02000000 100 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se1 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se1 02000000 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se1 02000000 100 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se2 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se2 02000000 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -se2 02000000 100 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -v -h > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -v -xxxxx > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se0 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se0 02000000 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se0 02000000 100 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se1 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se1 02000000 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se1 02000000 100 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se2 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se2 02000000 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -se2 02000000 100 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -v -h > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -v -xxxxx > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se0 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se0 02000000 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se0 02000000 100 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se1 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se1 02000000 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se1 02000000 100 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se2 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se2 02000000 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -se2 02000000 100 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -v -h > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -v -xxxxx > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se0 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se0 02000000 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se0 02000000 100 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se1 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se1 02000000 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se1 02000000 100 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se2 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se2 02000000 > run.out
checkFailure $?

echo "powerup"
${PREFIX}powerup -se2 02000000 100 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -v -h > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -v -xxxxx > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se0 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se0 02000000 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se0 02000000 100 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se1 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se1 02000000 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se1 02000000 100 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se2 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se2 02000000 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -se2 02000000 100 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -v -h > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -v -xxxxx > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se0 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se0 02000000 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se0 02000000 100 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se1 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se1 02000000 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se1 02000000 100 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se2 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se2 02000000 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -se2 02000000 100 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -v -h > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -v -xxxxx > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se0 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se0 02000000 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se0 02000000 100 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se1 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se1 02000000 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se1 02000000 100 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se2 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se2 02000000 > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -se2 02000000 100 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -v -h > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -v -xxxxx > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se0 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se0 02000000 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se0 02000000 100 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se1 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se1 02000000 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se1 02000000 100 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se2 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se2 02000000 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -se2 02000000 100 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -v -h > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -v -xxxxx > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se0 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se0 02000000 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se0 02000000 100 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se1 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se1 02000000 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se1 02000000 100 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se2 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se2 02000000 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -se2 02000000 100 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -v -h > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -v -xxxxx > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se0 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se0 02000000 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se0 02000000 100 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se1 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se1 02000000 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se1 02000000 100 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se2 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se2 02000000 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -se2 02000000 100 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -v -h > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -v -xxxxx > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se0 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se0 02000000 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se0 02000000 100 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se1 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se1 02000000 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se1 02000000 100 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se2 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se2 02000000 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -se2 02000000 100 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -v -h > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -v -xxxxx > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se0 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se0 02000000 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se0 02000000 100 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se1 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se1 02000000 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se1 02000000 100 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se2 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se2 02000000 > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -se2 02000000 100 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -v -h > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -v -xxxxx > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se0 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se0 02000000 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se0 02000000 100 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se1 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se1 02000000 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se1 02000000 100 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se2 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se2 02000000 > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -se2 02000000 100 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -v -h > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -v -xxxxx > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se0 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se0 02000000 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se0 02000000 100 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se1 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se1 02000000 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se1 02000000 100 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se2 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se2 02000000 > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -se2 02000000 100 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -v -h > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -v -xxxxx > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se0 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se0 02000000 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se0 02000000 100 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se1 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se1 02000000 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se1 02000000 100 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se2 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se2 02000000 > run.out
checkFailure $?

echo "shutdown"
${PREFIX}shutdown -se2 02000000 100 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -v -h > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -v -xxxxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se0 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se0 02000000 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se0 02000000 100 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se1 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se1 02000000 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se1 02000000 100 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se2 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se2 02000000 > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -se2 02000000 100 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -v -h > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -v -xxxxx > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se0 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se0 02000000 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se0 02000000 100 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se1 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se1 02000000 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se1 02000000 100 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se2 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se2 02000000 > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se2 02000000 100 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -v -h > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -v -xxxxx > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se0 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se0 02000000 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se0 02000000 100 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se1 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se1 02000000 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se1 02000000 100 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se2 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se2 02000000 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -se2 02000000 100 > run.out
checkFailure $?

echo "stirrandom"
${PREFIX}stirrandom -v -h > run.out
checkFailure $?

echo "stirrandom"
${PREFIX}stirrandom -v -xxxxx > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -v -h > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -v -xxxxx > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se0 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se0 02000000 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se0 02000000 100 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se1 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se1 02000000 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se1 02000000 100 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se2 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se2 02000000 > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -se2 02000000 100 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -v -h > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -v -xxxxx > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se0 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se0 02000000 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se0 02000000 100 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se1 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se1 02000000 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se1 02000000 100 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se2 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se2 02000000 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -se2 02000000 100 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -v -h > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -v -xxxxx > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se0 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se0 02000000 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se0 02000000 100 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se1 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se1 02000000 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se1 02000000 100 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se2 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se2 02000000 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -se2 02000000 100 > run.out
checkFailure $?

echo ""
echo "Usage Help for local utilities"
echo ""

echo "getcryptolibrary"
${PREFIX}getcryptolibrary -v -h > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -v -h > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -v -h > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -v -h > run.out
checkFailure $?

echo ""
echo "Missing arguments"
echo ""

echo "ActivateCredential"
${PREFIX}activatecredential -icred > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -ocred > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -is > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -ha > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -hk > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -pwda > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -pwdk > run.out
checkFailure $?

echo "ActivateCredential"
${PREFIX}activatecredential -pwda > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify - > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -ho > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -pwdo > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -hk > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -pwdk > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -halg > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -salg > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -qd > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -os > run.out
checkFailure $?

echo "Certify"
${PREFIX}certify -oa > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -ho > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -hk > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -pwdk > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -halg > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -salg > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -qd > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -tk > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -ch > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -os > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -oa > run.out
checkFailure $?

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo "certifyx509"
    ${PREFIX}certifyx509 -ho > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -pwdo > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -hk > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -pwdk > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -halg > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -rsa > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ecc > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ku > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -iob > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -bit > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -sub > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -opc > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -oa > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -otbs > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -os > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ocert > run.out
    checkFailure $?

fi

echo "changeeps"
${PREFIX}changeeps -pwda > run.out
checkFailure $?

echo "changepps"
${PREFIX}changepps -pwda > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -hi > run.out
checkFailure $?
echo "clear"
${PREFIX}clear -pwda > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -hi > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -pwda > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -state > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -hi > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -pwdp > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -adj > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -clock > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -iclock > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -addsec > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -hi > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -pwdp > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -hk > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -pt > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -s2 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -y2 > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -Kf > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -Lf > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -Ef > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -Cf > run.out
checkFailure $?

echo "commit"
${PREFIX}commit -pwdk > run.out
checkFailure $?

echo "contextload"
${PREFIX}contextload -if > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -ha > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -of > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp > run.out
checkFailure $?

echo "create"
${PREFIX}create -rsa > run.out
checkFailure $?

echo "create"
${PREFIX}create -ecc > run.out
checkFailure $?

echo "create"
${PREFIX}create -bl > run.out
checkFailure $?

echo "create"
${PREFIX}create -kt > run.out
checkFailure $?

echo "create"
${PREFIX}create -pol > run.out
checkFailure $?

echo "create"
${PREFIX}create -if > run.out
checkFailure $?

echo "create"
${PREFIX}create -nalg > run.out
checkFailure $?

echo "create"
${PREFIX}create -halg > run.out
checkFailure $?

echo "create"
${PREFIX}create -pwdk > run.out
checkFailure $?

echo "create"
${PREFIX}create -pwdp > run.out
checkFailure $?

echo "create"
${PREFIX}create -opu > run.out
checkFailure $?

echo "create"
${PREFIX}create -opr > run.out
checkFailure $?

echo "create"
${PREFIX}create -opem > run.out
checkFailure $?

echo "create"
${PREFIX}create -tk > run.out
checkFailure $?

echo "create"
${PREFIX}create -ch > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -root > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -pwde > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -pwdk > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -ecc > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -pwdp > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -pwde > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -pwdk > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -cakey > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -capwd > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -caalg > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -ecc > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -of > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hp > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -rsa > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -ecc > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -bl > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -pol > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -if > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -nalg > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -halg > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -pwdk > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -pwdp > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -opu > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -opr > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -opem > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -hi > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -pwdp > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -pwdpi > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -iu > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -opu > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -opem > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -tk > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -ch > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -ecc > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -bl > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -kt > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -pol > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -if > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -nalg > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -halg > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -pwd > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -pwd > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -nmt > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -nrt > run.out
checkFailure $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -lr > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -ho > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -pwdo > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -hp > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -ik > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -salg > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -oek > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -od > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -oss > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -hk > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -pwdk > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -ipwdk > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -halg > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -od > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -ic1 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -ic2 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -ic3 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -hk > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -halg > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -id > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -oc1 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -oc2 > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -oc3 > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -cv > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -of > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -ecc > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -oq > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -cf > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -hk > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -pwdk > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -if > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -of > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -if > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -pcrmax > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -ha > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -hs > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -pwds > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -if > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -of1 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -of2 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -of3 > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -of5 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -hi > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -ho > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -hp > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -pwda > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -ha > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -cap > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -pr > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -pc > run.out
checkFailure $?

echo "getcapability"
${PREFIX}getcapability -pc 0 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -pwde > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -hk > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -pwdk > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -halg > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -salg > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -qd > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -os > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -oa > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -by > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -of > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -pwde > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -hk > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -pwdk > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -hs > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -halg > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -qd > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -os > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -oa > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -od > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -hk > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -pwdk > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -pwde > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -halg > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -salg > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -qd > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -os > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -oa > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -hi > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -halg > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -if > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -ic > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -oh > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -tk > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -pwda > run.out
checkFailure $?

echo "hashsequencestart"
${PREFIX}hashsequencestart -halg > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -hi > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwdn > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwdni > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwda > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwdai > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -hi > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -he > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -pwda > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -state > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -hk > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -pwdk > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -halg > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -if > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -ic > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -os > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -hk > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -pwdk > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -pwda > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -halg > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -if > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -of > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -halg > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -ty > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -b > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -e > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -l > run.out
checkFailure $?

echo "import"
${PREFIX}import -hp > run.out
checkFailure $?

echo "import"
${PREFIX}import -pwdp > run.out
checkFailure $?

echo "import"
${PREFIX}import -ik > run.out
checkFailure $?

echo "import"
${PREFIX}import -ipu > run.out
checkFailure $?

echo "import"
${PREFIX}import -id > run.out
checkFailure $?

echo "import"
${PREFIX}import -iss > run.out
checkFailure $?

echo "import"
${PREFIX}import -salg > run.out
checkFailure $?

echo "import"
${PREFIX}import -opr > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -hp > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -pwdp > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -ipem > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -scheme > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -pwdk > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -opu > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -opr > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -nalg > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -halg > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -pol > run.out
checkFailure $?

echo "load"
${PREFIX}load -hp > run.out
checkFailure $?

echo "load"
${PREFIX}load -pwdp > run.out
checkFailure $?

echo "load"
${PREFIX}load -ipu > run.out
checkFailure $?

echo "load"
${PREFIX}load -ipr > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -hi > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -pwdk  > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -nalg > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -halg > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipu > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ider > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -scheme > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -ha > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -icred > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -in > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -ocred > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -os > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -ha > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -pwdn > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -hk > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -pwdk > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -halg > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -salg > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -sz > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -off > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -os > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -oa > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -od > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -ha > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -pwdo > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth -pwdn > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -ha > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -hi > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -pwdp > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -hia > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -pwdn > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -nalg > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -sz > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -ty > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -pol > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace +at > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -ha > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -pwdn > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -ic > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -if > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -hia > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -pwd > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -ha > run.out
checkFailure $?

echo "nvincrement"
${PREFIX}nvincrement -pwdn > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -hia > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -ha > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -pwdn > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -sz > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -ocert > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -off > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -id > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -hia > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -ha > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -pwdn > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -ha > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -nalg > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -opu > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -on > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -ha > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -pdwn > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -bit > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -hi > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -ha > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -pwdp > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -ha > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -pwdp > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -pwdn > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -hia > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -ha > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -pwdn > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -ic > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -if > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -id > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -off > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -hia > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -ha > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -pwdn > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -hp > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -ho > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -pwdo > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -pwdn > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -ipwdn > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -opr > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate -pwdp > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -ha > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -ic > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -if > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -of1 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -of2 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -of3 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -of5 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -halg > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ic > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -if > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread - ha> run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -halg > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -of > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -ahalg > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -iosad > run.out
checkFailure $?

echo "pcrreset"
${PREFIX}pcrreset -ha > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -ha > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -appr > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -pref > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -skn > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -tk > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -hi > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -ha > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -pwda > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -hs > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -ha > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -ha > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -cc > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ha > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ic > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -if > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -off > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -op > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -ha > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -cp > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -ha > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -inpn > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -ion > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -io > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -ha > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -of > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -halg > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -if > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -of > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -ha > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -nh > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv - > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -hs > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -ws > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -ha > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -if > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -ha > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -ha > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -halg > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -bm > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -ha > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -ha > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -hs > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -in > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -cp > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -pref > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -exp > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -pwde > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -tk > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -to > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -ha > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -in > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -cp > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -pref > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -exp > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -sk > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -is > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -pwdk > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -ha > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -te > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -to > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -cp > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -pref > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -na > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -hi > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -tk > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -invpu > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ipu > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ipem > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ider > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -on > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -nalg > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -halg > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -hp > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -ha > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -pwdk > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -halg > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -salg > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -qd > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -os > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -os > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -palg > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -otime > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -oclock > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -ho > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -opu > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic -opem > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -ho > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -pwdo > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -hn > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -id > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -in > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -iss > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -od > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -oss > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -hk > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -pwdk > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -ipwdk > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -ie > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -od > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -oid > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -hk > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -id > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -oe > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hs > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hi > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -pwds > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -if > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -of > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -tk > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -hs > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -pwds > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate -if > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -hi > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -pwda > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -halg > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -set > run.out
checkFailure $?

echo "setcommandcodeauditstatus"
${PREFIX}setcommandcodeauditstatus -clr > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -hi > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -pwda > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -pol > run.out
checkFailure $?

echo "setprimarypolicy"
${PREFIX}setprimarypolicy -halg > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -hk > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -if > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -pwdk > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -halg > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -salg > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -scheme > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -cf > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -ipu > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -os > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -tk > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -halg > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -hs > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -bi > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -pwdb > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -sym > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -on > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -loc > run.out
checkFailure $?

echo "stirrandom"
${PREFIX}stirrandom -if > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -ipu > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -opem > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -ipu > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -pt > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -ha > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -pwd > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal -of > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -if > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -ih > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -is > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -hk > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -ipem > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -ihmac > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -tk > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -halg > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -hk > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -pwdk > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -qsb > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -qeb > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -cf > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -scheme > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -z1 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -z1 > run.out
checkFailure $?

echo ""
echo "policycommandcode"
echo ""

for CC in 11f 120 121 122 124 125 126 127 128 129 12a 12b 12c 12d 12e 130 131 132 133 134 135 136 137 138 139 13a 13b 13c 13d 13e 13f 140 142 143 144 145 146 147 148 149 14a 14b 14c 14d 14e 14f 150 151 152 153 154 155 156 157 158 159 15b 15c 15d 15e 160 161 162 163 164 165 167 168 169 16a 16b 16c 16d 16e 16f 170 171 172 173 174 176 177 178 17a 17b 17c 17d 17e 17f 180 181 182 183 184 185 186 187 188 189 18a 18b 18c 18d 18e 18f 190 191 192 193 197 199 19A
do

    echo "startauthsession"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "policycommandcode"
    ${PREFIX}policycommandcode -ha 03000000 -v -cc ${CC} > run.out
    checkSuccess $?

    echo "Flush the session"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?

done

echo ""
echo "Missing Parameter"
echo ""

echo "activatecredential"
${PREFIX}activatecredential > run.out
checkFailure $?

echo "activatecredential"
${PREFIX}activatecredential -ha 1 > run.out
checkFailure $?

echo "activatecredential"
${PREFIX}activatecredential -ha 1 -hk 1 > run.out
checkFailure $?

echo "activatecredential"
${PREFIX}activatecredential  -ha 1 -hk 1 -icred xxx > run.out
checkFailure $?

echo "certify"
${PREFIX}certify > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -ho 1 > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -halg xxx > run.out
checkFailure $?

echo "certify"
${PREFIX}certify -salg xxx > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -halg xxx > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -salg xxx > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -ho 1 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -ho 1 -hk 1 > run.out
checkFailure $?

echo "certifycreation"
${PREFIX}certifycreation -ho 1 -hk 1 -tk xxx > run.out
checkFailure $?

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo "certifyx509"
    ${PREFIX}certifyx509 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -halg xxx > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ecc xxx > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ho 1 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ho 1 -hk 1 > run.out
    checkFailure $?

    echo "certifyx509"
    ${PREFIX}certifyx509 -ho 1 -hk 1 -rsa 2048 -ecc nistp256 > run.out
    checkFailure $?

fi

echo "changeeps"
${PREFIX}changeeps -pwda xxx > run.out
checkFailure $?

echo "clear"
${PREFIX}clear -pwda xxx > run.out
checkFailure $?

echo "dictionaryattacklockreset 1"
${PREFIX}dictionaryattacklockreset > run.out
checkSuccess $?

echo "clear"
${PREFIX}clear -pwda xxx -hi p > run.out
checkFailure $?

echo "dictionaryattacklockreset 2"
${PREFIX}dictionaryattacklockreset > run.out
checkSuccess $?

echo "clear"
${PREFIX}clear -pwda xxx -hi x > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -pwda xxx -hi x > run.out
checkFailure $?

echo "clearcontrol"
${PREFIX}clearcontrol -pwda xxx > run.out
checkFailure $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -hi o > run.out
checkSuccess $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -hi p > run.out
checkSuccess $?

echo "clockrateadjust"
${PREFIX}clockrateadjust -hi x > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -iclock xxx -hi x > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -pwdp xxx > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -clock 123 > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -clock 123 -iclock xxx > run.out
checkFailure $?

echo "clockset"
${PREFIX}clockset -clock 123 -hi x > run.out
checkFailure $?

echo "contextsave"
${PREFIX}contextsave -ha 1 > run.out
checkFailure $?

echo "create"
${PREFIX}create -gp > run.out
checkFailure $?

echo "create"
${PREFIX}create -116 > run.out
checkFailure $?

echo "create"
${PREFIX}create -ecc xxx > run.out
checkFailure $?

echo "create"
${PREFIX}create -kt nf > run.out
checkFailure $?

echo "create"
${PREFIX}create -kt np > run.out
checkFailure $?

echo "create"
${PREFIX}create -kt ed > run.out
checkFailure $?

echo "create"
${PREFIX}create -kt xxx > run.out
checkFailure $?

echo "create"
${PREFIX}create -halg xxx > run.out
checkFailure $?

echo "create"
${PREFIX}create -nalg xxx > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp 1 -kt p -kt p > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp 1 -bl > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp 1 -dau > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp 1 -dar > run.out
checkFailure $?

echo "create"
${PREFIX}create -hp 1 -gp -if xxx > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa 2048 -high > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa 4096 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa 1 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -ecc nistp521 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -ecc xxx > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -te -no > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa 2048 > run.out
checkFailure $?

echo "createek"
${PREFIX}createek -rsa 2048 -ecc nistp256 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -noflush > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 2048 -high > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 4096 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 1 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -ecc nistp521 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -caalg xxx > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -pwdk xxx > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 2048 -cakey cakey.pem -vv > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 2048 -ecc nistp256 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -rsa 2048 > run.out
checkFailure $?

echo "createekcert"
${PREFIX}createekcert -ecc xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -deo > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -des > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -sir > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hk > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hkr > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -dp > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -gp > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -116 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -ecc xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt nf > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt np > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt ed > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -uwa > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -halg sha1 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -halg sha256 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -halg sha384 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -halg xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -nalg sha1 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -nalg sha256 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -nalg sha384 > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -nalg xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hp 1 -pol > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hp 1 -bl > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -hp 1 -st -if xxx > run.out
checkFailure $?

echo "createloaded"
${PREFIX}createloaded -kt xxx > run.out
checkFailure $?

echo "createprimary -den"
${PREFIX}createprimary -den -pwdp xxx > run.out
checkFailure $?

echo "createprimary -gp"
${PREFIX}createprimary -gp -pwdp xxx > run.out
checkFailure $?

echo "createprimary -116"
${PREFIX}createprimary -116 -pwdp xxx > run.out
checkFailure $?

echo "createprimary -ecc xxx"
${PREFIX}createprimary -ecc xxx > run.out
checkFailure $?

echo "createprimary -kt ed "
${PREFIX}createprimary -kt ed > run.out
checkFailure $?

echo "createprimary -kt xxx"
${PREFIX}createprimary -kt xxx > run.out
checkFailure $?

echo "createprimary -uwa"
${PREFIX}createprimary -uwa -pwdp xxx > run.out
checkFailure $?

echo "createprimary -da"
${PREFIX}createprimary -da -pwdp xxx > run.out
checkFailure $?

echo "createprimary -halg xxx"
${PREFIX}createprimary -halg xxx > run.out
checkFailure $?

echo "createprimary -nalg xxx"
${PREFIX}createprimary -nalg xxx > run.out
checkFailure $?

echo "createprimary -pwdk"
${PREFIX}createprimary -pwdk > run.out
checkFailure $?

echo "createprimary -dar"
${PREFIX}createprimary -dar > run.out
checkFailure $?

echo "createprimary -ecc nistp256"
${PREFIX}createprimary -ecc nistp256 -daa -if xxx > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -pwdp xxx -pwdpi xxx  > run.out
checkFailure $?

echo "createprimary"
${PREFIX}createprimary -hi x > run.out
checkFailure $?

echo "dictionaryattacklockreset"
${PREFIX}dictionaryattacklockreset -pwd "" > run.out
checkSuccess $?

echo "dictionaryattackparameters"
${PREFIX}dictionaryattackparameters -lr 1 > run.out
checkSuccess $?

echo "duplicate"
${PREFIX}duplicate -salg xxx > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -oek xxx > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -ho 1 -ik xxx > run.out
checkFailure $?

echo "duplicate"
${PREFIX}duplicate -ho 1 -salg aes > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -ipwdk xxx > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -halg xxx > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -hk 1 > run.out
checkFailure $?

echo "eccdecrypt"
${PREFIX}eccdecrypt -hk 1 -ic1 xxx -ic2 xxx -ic3 xxx -pwdk xxx -ipwdk xxx > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -halg xxx  > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt  > run.out
checkFailure $?

echo "eccencrypt"
${PREFIX}eccencrypt -hk 1  > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -cv xxx > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters -of xxx > run.out
checkFailure $?

echo "eccparameters"
${PREFIX}eccparameters > run.out
checkFailure $?

echo "ecephemeral"
${PREFIX}ecephemeral -ecc xxx > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -hk 1 > run.out
checkFailure $?

echo "encryptdecrypt"
${PREFIX}encryptdecrypt -hk 1 -if encryptdecrypt.c > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -nospec > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -ns > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -pcrmax 8 > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -if xxx > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -if xxx -nospec -sim > run.out
checkFailure $?

echo "eventextend"
${PREFIX}eventextend -if xxx -nospec > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete > run.out
checkFailure $?

echo "eventsequencecomplete"
${PREFIX}eventsequencecomplete -hs 1 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -pwda xxx > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -ho 1 > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -ho 1 -hp 1 -hi o > run.out
checkFailure $?

echo "evictcontrol"
${PREFIX}evictcontrol -ho 1 -hp 1 -hi x > run.out
checkFailure $?

echo "flushcontext"
${PREFIX}flushcontext -ha 1 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -pwde xxx > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -halg xxx > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -salg xxx > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -hk 1 > run.out
checkFailure $?

echo "getcommandauditdigest"
${PREFIX}getcommandauditdigest -halg sha256 -salg rsa > run.out
checkFailure $?

echo "getrandom"
${PREFIX}getrandom -by 100000 > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -pwde xxx > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -halg xxx > run.out
checkFailure $?

echo "getsessionauditdigest"
${PREFIX}getsessionauditdigest -hs 1 > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -pwde xxx > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -halg xxx > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime -salg xxx > run.out
checkFailure $?

echo "gettime"
${PREFIX}gettime > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -halg xxx > run.out
checkFailure $?

echo "hash"
${PREFIX}hash -ns > run.out
checkFailure $?

echo "hash"
${PREFIX}hash > run.out
checkFailure $?

echo "hash -if xxx -ic xxx"
${PREFIX}hash -if xxx -ic xxx > run.out
checkFailure $?

echo "hash -hi e -ic xxx"
${PREFIX}hash -hi e -ic xxx > run.out
checkSuccess $?

echo "hash -hi o -ic xxx"
${PREFIX}hash -hi o -ic xxx > run.out
checkSuccess $?

echo "hash -hi xxx -ic xxx"
${PREFIX}hash -hi xxx -ic xxx > run.out
checkFailure $?

echo "hash- if encryptdecrypt.c"
${PREFIX}hash -if encryptdecrypt.c > run.out
checkFailure $? 

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -hi x> run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwdn x -pwdni x > run.out
checkFailure $?

echo "hierarchychangeauth"
${PREFIX}hierarchychangeauth -pwda x -pwdai x > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -hi e  > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -hi o > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -hi x > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -he e  > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -he o > run.out
checkFailure $?

echo "hierarchycontrol"
${PREFIX}hierarchycontrol -he x > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -halg xxx > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -hk 1 > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -hk 1 -ic 1 -if xxx > run.out
checkFailure $?

echo "hmac"
${PREFIX}hmac -hk 1 -if encryptdecrypt.c > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart -halg xxx > run.out
checkFailure $?

echo "hmacstart"
${PREFIX}hmacstart > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -halg xxx > run.out
checkFailure $?

echo "imaextend -ty 3"
${PREFIX}imaextend -ty 3 > run.out
checkFailure $?

echo "imaextend -b 0"
${PREFIX}imaextend -b 0 > run.out
checkFailure $?

echo "imaextend -e 0"
${PREFIX}imaextend -e 0 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -l 1 > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend > run.out
checkFailure $?

echo "imaextend"
${PREFIX}imaextend -if xxx > run.out
checkFailure $?

echo "import -salg xxx"
${PREFIX}import -salg xxx > run.out
checkFailure $?

echo "import -salg aes"
${PREFIX}import -salg aes > run.out
checkFailure $?

echo "import -ik 1 "
${PREFIX}import -ik 1 > run.out
checkFailure $?

echo "import -ik 1 -ipu xxx -id xxx"
${PREFIX}import -ik 1 -ipu xxx -id xxx > run.out
checkFailure $?

echo "import -ik 1 -ipu xxx -id xxx"
${PREFIX}import -salg aes -ik 1 -ipu xxx -id xxx > run.out
checkFailure $?

echo "import -ik 1 -ipu xxx -id xxx"
${PREFIX}import -hp 1 -salg aes -ik 1 -ipu xxx -id xxx > run.out
checkFailure $?

echo "import -ik 1 -ipu xxx -id xxx"
${PREFIX}import -hp 1 -salg aes -ik 1 -ipu xxx -iss xxx > run.out
checkFailure $?

echo "import -ik 1 -ipu xxx -id xxx -iss xxx"
${PREFIX}import -ik 1 -ipu xxx -id xxx -iss xxx > run.out
checkFailure $?

echo "import -salg aes -ik 1 -ipu xxx -id xxx -iss xxx"
${PREFIX}import -hp 1 -salg aes -ik 1 -ipu xxx -id xxx -iss xxx > run.out
checkFailure $?

echo "import"
${PREFIX}import > run.out
checkFailure $?

echo "import"
${PREFIX}import -hp 1 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -si -scheme rsapss > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -st -scheme rsapss > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -scheme rsapss > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -scheme xxx > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -halg xxx > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -nalg xxx > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -hp 1 > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -hp 1 -ipem xxx -si -st > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem -hp 1 -ipem xxx > run.out
checkFailure $?

echo "importpem"
${PREFIX}importpem  -hp 1 -ipem xxx -opu xxx> run.out
checkFailure $?

echo "load"
${PREFIX}load > run.out
checkFailure $?

echo "load"
${PREFIX}load -hp 1> run.out
checkFailure $?

echo "load"
${PREFIX}load -hp 1 -ipr xxx > run.out
checkFailure $?

echo "load"
${PREFIX}load > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -hi x > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -halg xxx > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -nalg xxx > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -scheme xxx > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -st -scheme rsassa > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -si -st > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -pwdk xxx > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -hi o > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -hi e > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -hi n > run.out
checkFailure $?

echo "loadexternal"
${PREFIX}loadexternal -ipem xxx -hi x > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -ha 1 > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential -ha 1 -icred xxx > run.out
checkFailure $?

echo "makecredential"
${PREFIX}makecredential > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -halg xxx > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -salg xxx > run.out
checkFailure $?

echo "nvcertify missing -kh"
${PREFIX}nvcertify > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -hk 1 > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -hia > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify -hk 1 -ha 01000000 -hia x > run.out
checkFailure $?

echo "nvcertify"
${PREFIX}nvcertify > run.out
checkFailure $?

echo "nvchangeauth"
${PREFIX}nvchangeauth > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -nalg xxx > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace +at xxx > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at ow > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at or > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at pw > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at pr > run.out
checkFailure $?

echo "nvdefinespace"
${PREFIX}nvdefinespace -at xxx > run.out
checkFailure $?

echo "nvdefinespace -ty o -ty c "
${PREFIX}nvdefinespace -ha 01000000 -ty o -ty c > run.out
checkFailure $?

echo "nvdefinespace -hia xxx"
${PREFIX}nvdefinespace -ha 01000000 -hia xxx > run.out
checkFailure $?

echo "nvdefinespace -hi xxx"
${PREFIX}nvdefinespace -ha 01000000 -hi xxx > run.out
checkFailure $?

echo "nvdefinespace -ty x"
${PREFIX}nvdefinespace -ha 01000000 -hi p -ty x > run.out
checkFailure $?

echo "nvdefinespace policy mismatch"
${PREFIX}nvdefinespace -ha 01000000 -hia p -hi p -pol policies/sha1aaa.bin > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -ha 20000000 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -ha 01000000 > run.out
checkFailure $?

echo "nvextend"
${PREFIX}nvextend -ha 01000000 -ic xxx -if xxx > run.out
checkFailure $?

echo "nvglobalwritelock"
${PREFIX}nvglobalwritelock -hia x > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -of > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -sz 70000 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread  -ha 01000000 -hia x > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -id > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -id 1 > run.out
checkFailure $?

echo "nvread"
${PREFIX}nvread -ha 01000000 -id 1 1 -sz 4 > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock > run.out
checkFailure $?

echo "nvreadlock"
${PREFIX}nvreadlock -ha 01000000 -hia x > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic -nalg xxx > run.out
checkFailure $?

echo "nvreadpublic"
${PREFIX}nvreadpublic > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -pwdn > run.out
checkFailure $?

echo "nvsetbits"
${PREFIX}nvsetbits -bit 65 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -pwdp > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -ha 30000000 > run.out
checkFailure $?

echo "nvundefinespace"
${PREFIX}nvundefinespace -ha 01000000 -hi x > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -pwdp > run.out
checkFailure $?

echo "nvundefinespacespecial"
${PREFIX}nvundefinespacespecial -ha 30000000 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -id > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -id 1 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -ha 30000000 > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -ha 01000000 -if xxx -ic xxx > run.out
checkFailure $?

echo "nvwrite"
${PREFIX}nvwrite -ha 01000000 -hia x > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -ha 30000000 > run.out
checkFailure $?

echo "nvwritelock"
${PREFIX}nvwritelock -ha 01000000 -hia x > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -hp 1 > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -hp 1 -ho 1 -pwdn xxx -ipwdn xxx > run.out
checkFailure $?

echo "objectchangeauth"
${PREFIX}objectchangeauth -hp 1 -ho 1 -pwdn "" > run.out
checkFailure $?

echo "pcrallocate -pwdp xxx "
${PREFIX}pcrallocate -pwdp xxx > run.out
checkFailure $?

echo "pcrallocate +sha1 +sha1 "
${PREFIX}pcrallocate -pwdp xxx +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 +sha1 > run.out
checkFailure $?

echo "pcrallocate -sha1 -sha1"
${PREFIX}pcrallocate -pwdp xxx -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 -sha1 > run.out
checkFailure $?

echo "pcrallocate sha256 +sha256 "
${PREFIX}pcrallocate -pwdp xxx +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 +sha256 > run.out
checkFailure $?

echo "pcrallocate -sha256 -sha256"
${PREFIX}pcrallocate -pwdp xxx -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 > run.out
checkFailure $?

echo "pcrallocate +sha384 +sha384"
${PREFIX}pcrallocate -pwdp xxx +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 +sha384 > run.out
checkFailure $?

echo "pcrallocate -sha384 -sha384"
${PREFIX}pcrallocate -pwdp xxx -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 -sha384 > run.out
checkFailure $?

echo "pcrallocate +sha512 +sha512"
${PREFIX}pcrallocate -pwdp xxx +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 +sha512 > run.out
checkFailure $?

echo "pcrallocate -sha512 -sha512"
${PREFIX}pcrallocate -pwdp xxx -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 -sha512 > run.out
checkFailure $?

echo "pcrallocate"
${PREFIX}pcrallocate > run.out
checkFailure $?

echo "pcrallocate sha1 -pwdp xxx"
${PREFIX}pcrallocate +sha1 -pwdp xxx > run.out
checkFailure $?

echo "pcrevent -ha 0 -ic x"
${PREFIX}pcrevent -ha 0 -ic x > run.out
checkSuccess $?

echo "pcrevent"
${PREFIX}pcrevent -ha 24 -ic x > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -ha 0 > run.out
checkFailure $?

echo "pcrevent"
${PREFIX}pcrevent -ha 0 -ic x -if xxx > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 -halg sha256 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -halg xxx > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 24 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 0 > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 0 -ic x -if xxx > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 0 -ic 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678990123456789901234567899012345678990123456789  > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 0 -if policies/rsapubkey.pem > run.out
checkFailure $?

echo "pcrextend"
${PREFIX}pcrextend -ha 0 -ic x -v > run.out
checkSuccess $?

echo "pcrread -ha"
${PREFIX}pcrread -ha > run.out
checkFailure $?

echo "pcrread" -ha 0 -halg sha1 -halg sha256
${PREFIX}pcrread -ha 0 -halg sha1 -halg sha256 > run.out
checkSuccess $?

echo "pcrread ha 0 -halg sha1 -halg sha1"
${PREFIX}pcrread -ha 0 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1 -halg sha1  > run.out
checkFailure $?

echo "pcrread -ha 0 -halg xxx"
${PREFIX}pcrread -ha 0 -halg xxx > run.out
checkFailure $?

echo "pcrread -ha 0 -ahalg xxx"
${PREFIX}pcrread -ha 0 -ahalg xxx > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrread -ha 0 -ns > run.out
checkSuccess $?

echo "pcrread"
${PREFIX}pcrread -ha 24 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrreset -ha 24 > run.out
checkFailure $?

echo "pcrread"
${PREFIX}pcrreset -ha 0 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -pref > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -ha 1 > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -ha 1 -appr xxx > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -ha 1 -appr xxx -skn xxx > run.out
checkFailure $?

echo "policyauthorize"
${PREFIX}policyauthorize -ha 1 -appr policies/sha1aaa.bin -skn xxx -tk xxx -pref policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -pwda xxx > run.out
checkFailure $?

echo "policyauthorizenv"
${PREFIX}policyauthorizenv -ha 1 -hs 1 -hi x > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue > run.out
checkFailure $?

echo "policyauthvalue"
${PREFIX}policyauthvalue -ha 1 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -ha 1 > run.out
checkFailure $?

echo "policycommandcode"
${PREFIX}policycommandcode -ha 02000000 -cc 1 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ic > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ha 1 > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ha 1 -if policies/sha1aaa.bin > run.out
checkFailure $?

echo "policycountertimer"
${PREFIX}policycountertimer -ha 1 -ic 1111 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -ha 1 > run.out
checkFailure $?

echo "policycphash"
${PREFIX}policycphash -ha 1 -cp policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -ha 1 -inpn 1 > run.out
checkFailure $?

echo "policyduplicationselect"
${PREFIX}policyduplicationselect -ha 1 -inpn 1 -ion policies/sha1aaa.bin > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest > run.out
checkFailure $?

echo "policygetdigest"
${PREFIX}policygetdigest -ha 1 > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker > run.out
checkFailure $?

echo "policymaker -if xxx"
${PREFIX}policymaker -if xxx > run.out
checkFailure $?

echo "policymaker -halg sha1"
${PREFIX}policymaker -halg sha1 -if policies/policysignedsha1.txt -of tmp.bin -pr > run.out
checkSuccess $?

echo "policymaker -halg sha256"
${PREFIX}policymaker -halg sha256 -if policies/policysignedsha256.txt -of tmp.bin -nz > run.out
checkSuccess $?

echo "policymakerr -halg sha384"
${PREFIX}policymaker -halg sha384 -if policies/policysignedsha384.txt -of tmp.bin > run.out
checkSuccess $?

echo "policymaker -halg sha512"
${PREFIX}policymaker -halg sha512 -if policies/policysignedsha512.txt -of tmp.bin > run.out
checkSuccess $?

echo "policymaker -halg xxx"
${PREFIX}policymaker -halg xxx -if policies/policysignedsha1.txt -of tmp.bin > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -if policies/policycountertimer.txt -of tmp.bin -pr -v > run.out
checkSuccess $?

echo "policymaker -halg sha1"
${PREFIX}policymaker -halg sha1 -if policies/policysignedsha1.txt -of tmp.bin -pr -of xxx/xxx > run.out
checkFailure $?

echo "policymaker"
${PREFIX}policymaker -if policies/policysignedsha1.bin -of tmp.bin > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -ha 1 > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash -ha 1 -nh policies/rsapubkey.pem > run.out
checkFailure $?

echo "policynamehash"
${PREFIX}policynamehash  -ha 1 -nh policies/sha1aaa.bin > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -pwda > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -hs > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ic > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -if > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ic 1111 > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -hi > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha 1 -hs 1 -ic x -hi o > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha 1 -hs 1 -ic x -hi p > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha 1 -hs 1 -ic x -hi x > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -off > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -op > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha 1 -hs 1  > run.out
checkFailure $?

echo "policynv"
${PREFIX}policynv -ha 1 -hs 1 -ic x -if xxx > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten > run.out
checkFailure $?

echo "policynvwritten"
${PREFIX}policynvwritten -hs 1 -ws x > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -if x -if x -if x -if x -if x -if x -if x -if x -if x > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -if x -if x -if x -if x -if x -if x -if x -if x > run.out
checkFailure $?

echo "policyor"
${PREFIX}policyor -ha 1 -if x > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword > run.out
checkFailure $?

echo "policypassword"
${PREFIX}policypassword -ha 1 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -halg xxx > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -bm q > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -ha > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -ha 1 > run.out
checkFailure $?

echo "policypcr"
${PREFIX}policypcr -ha 1 -bm 1 > run.out
checkFailure $?

echo "policyrestart"
${PREFIX}policyrestart -ha 1 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -cp > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -pref > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -ha 1 > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -ha 1 -hs 1 -cp xxx > run.out
checkFailure $?

echo "policysecret"
${PREFIX}policysecret -ha 1 -hs 1 -pref xxx > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -pref > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -tk > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -halg xxx > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -halg > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk 1 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk 1 -ha 1 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk 1 -ha 1 -sk 1 -is 1 > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk 1 -ha 1 -sk 1 -pref xxx > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -hk 1 -ha 1 -sk 1 -is xxx > run.out
checkFailure $?

echo "policysigned"
${PREFIX}policysigned -to > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -ha 1 > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate -ha 1 -te xxx > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate > run.out
checkFailure $?

echo "policytemplate"
${PREFIX}policytemplate > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -cp > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -cp xxx > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -pref > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -pref xxx > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to ooo > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to xxx -na nnn > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to xxx -hi h > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk kkk > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin -cp policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi p -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi e -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi o -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
checkFailure $?

echo "policyticket"
${PREFIX}policyticket -ha 1 -to policies/sha1aaa.bin -hi h -tk policies/sha1aaa.bin -pref policies/sha1aaa.bin > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -halg xxx > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -nalg xxx > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -si -scheme > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -si -scheme rsassa > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -si -scheme rsapss > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -si -scheme null > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -si -scheme xxx > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -st > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -den > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -uwa > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ns > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -xxx > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ns > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ipem xxx -ider yyy > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ipem xxx -si -st > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ipu xxx -si -uwa > run.out
checkFailure $?

echo "publicname"
${PREFIX}publicname -ider ddd -st > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -hp 24 > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -hk > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -halg xxx > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -palg xxx > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -salg xxx > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -oa > run.out
checkFailure $?

echo "quote"
${PREFIX}quote > run.out
checkFailure $?

echo "quote"
${PREFIX}quote -hk 1 > run.out
checkFailure $?

echo "readclock"
${PREFIX}readclock -otime > run.out
checkFailure $?

echo "readpublic"
${PREFIX}readpublic > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -ho 1 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -ho 1 -hn 1 > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -ho 1 -hn 1 id xxx > run.out
checkFailure $?

echo "rewrap"
${PREFIX}rewrap -ho 1 -hn 1 -id xxx -in xxx > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -oid xxx > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -hk 1 > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -hk 1 -ie xxx > run.out
checkFailure $?

echo "rsadecrypt"
${PREFIX}rsadecrypt -hk 1 -ie xxx -pwdk xxx -ipwdk xxx > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -hk 1 > run.out
checkFailure $?

echo "rsaencrypt"
${PREFIX}rsaencrypt -hk 1 -id xxx > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hs 1 > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hs 1 -if xxx > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hi x > run.out
checkFailure $?

echo "sequencecomplete"
${PREFIX}sequencecomplete -hs 1 -if policies/sha1aaa.bin > run.out
checkFailure $?

echo "sequenceupdate"
${PREFIX}sequenceupdate > run.out
checkFailure $?

echo "sequenceupdate -hs 1"
${PREFIX}sequenceupdate -hs 1 > run.out
checkFailure $?

echo "sequenceupdate -hs 1 -if policies/sha1aaa.bin"
${PREFIX}sequenceupdate -hs 1 -if policies/sha1aaa.bin > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx -set 00000000"
${PREFIX}setcommandcodeauditstatus -pwda xxx -set 00000001 > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx -halg sha1"
${PREFIX}setcommandcodeauditstatus -pwda xxx -halg sha1 > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx -halg sha256"
${PREFIX}setcommandcodeauditstatus -pwda xxx -halg sha256 > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx -halg sha384"
${PREFIX}setcommandcodeauditstatus -pwda xxx -halg sha384 > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx -halg sha512"
${PREFIX}setcommandcodeauditstatus -pwda xxx -halg sha512 > run.out
checkFailure $?

echo "setcommandcodeauditstatus -halg xxx"
${PREFIX}setcommandcodeauditstatus -halg xxx > run.out
checkFailure $?

echo "setcommandcodeauditstatus -set 00000000 -hi o"
${PREFIX}setcommandcodeauditstatus -set 00000000 -hi o > run.out
checkSuccess $?

echo "setcommandcodeauditstatus -set 00000000 -hi x"
${PREFIX}setcommandcodeauditstatus -set 00000000 -hi x > run.out
checkFailure $?

echo "setcommandcodeauditstatus -pwda xxx"
${PREFIX}setcommandcodeauditstatus -pwda xxx > run.out
checkFailure $?

echo "setprimarypolicy -halg sha1"
${PREFIX}setprimarypolicy -halg sha1 > run.out
checkFailure $?

echo "setprimarypolicy -halg xxx"
${PREFIX}setprimarypolicy -halg xxx > run.out
checkFailure $?

echo "setprimarypolicy -pol policies/sha1aaa.bin"
${PREFIX}setprimarypolicy -pol policies/sha1aaa.bin > run.out
checkFailure $?

echo "setprimarypolicy -hi l"
${PREFIX}setprimarypolicy -hi l > run.out
checkSuccess $?

echo "setprimarypolicy -hi e"
${PREFIX}setprimarypolicy -hi e > run.out
checkSuccess $?

echo "setprimarypolicy -hi o"
${PREFIX}setprimarypolicy -hi o > run.out
checkSuccess $?

echo "setprimarypolicy -hi x"
${PREFIX}setprimarypolicy -hi x > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -halg xxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -salg xxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -scheme eca > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -scheme xxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -if xxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -kh 1 -if xxx > run.out
checkFailure $?

echo "sign"
${PREFIX}sign -kh 1 -if xxx -scheme ecdaa > run.out
checkFailure $?

echo "signapp"
${PREFIX}signapp > run.out
checkFailure $?

echo "signapp"
${PREFIX}signapp -ic > run.out
checkFailure $?

echo "signapp"
${PREFIX}signapp -xxx > run.out
checkFailure $?

echo "signapp"
${PREFIX}signapp > run.out
checkFailure $?

echo "signapp"
${PREFIX}signapp > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -halg xxx > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -sym xxx > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -pwdb xxx > run.out
checkFailure $?

echo "startauthsession"
${PREFIX}startauthsession -se x > run.out
checkFailure $?

echo "startup"
${PREFIX}startup > run.out
checkFailure $?

echo "startup"
${PREFIX}startup -loc 7 > run.out
checkFailure $?

echo "startup"
${PREFIX}startup > run.out
checkFailure $?

echo "startup"
${PREFIX}startup > run.out
checkFailure $?

echo "startup"
${PREFIX}startup > run.out
checkFailure $?

echo "startup"
${PREFIX}startup > run.out
checkFailure $?

echo "stirrandom"
${PREFIX}stirrandom > run.out
checkFailure $?

echo "stirrandom"
${PREFIX}stirrandom -if encryptdecrypt.c > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -xxx > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -ipu xxx > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem -ipu xxx -opem xxx > run.out
checkFailure $?

echo "tpm2pem"
${PREFIX}tpm2pem > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -xxx > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -ipu xxx > run.out
checkFailure $?

echo "tpmpublic2eccpoint"
${PREFIX}tpmpublic2eccpoint -ipu  signrsa2048nfpub.bin -pt policies/tmp.bin > run.out
checkFailure $?

echo "unseal"
${PREFIX}unseal > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -halg xxx  > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -ih xxx t > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -hk 1 > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature -hk 1 -if xxx > run.out
checkFailure $?

echo "verifysignature"
${PREFIX}verifysignature > run.out
checkFailure $?

echo "writeapp"
${PREFIX}writeapp -xxx > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -scheme xxx > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -hk 1 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -hk 1 -qsb xxx > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -hk 1 -qsb xxx -qeb xxx > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -z1 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -z2 > run.out
checkFailure $?

echo "zgen2phase"
${PREFIX}zgen2phase -pwd > run.out
checkFailure $?

# cleanup

rm -rf tmp.bin

exit


echo "policymakerpcr"
${PREFIX}policymakerpcr > run.out
checkFailure $?

echo "printattr"
${PREFIX}printattr > run.out
checkFailure $?

echo "returncode"
${PREFIX}returncode > run.out
checkFailure $?

echo "timepacket"
${PREFIX}timepacket > run.out
checkFailure $?

echo "tpmproxy"
${PREFIX}tpmproxy > run.out
checkFailure $?

