#!/bin/bash
#

# for rapid prototyping with scripts
export TPM_ENCRYPT_SESSIONS=0
export TPM_DATA_DIR=.
PREFIX=./

checkSuccess()
{
    if [ $1 -ne 0 ]; then
	echo " ERROR:"
	cat run.out
	exit 255
    else
	echo " INFO:"
    fi
}

checkFailure()
{
    if [ $1 -eq 0 ]; then
	echo " ERROR:"
	cat run.out
	exit 255
    else
	echo " INFO:"
    fi
}

# just for the prototype, start with basic keys


# ./reg.sh -0

echo -n 123 > wtmp.txt

echo ""
echo "TPM 1.2"
echo ""

echo "Reboot"
${PREFIX}tpminit -v > run.out
checkSuccess $?

echo "Startup"
${PREFIX}startup -v > run.out
checkSuccess $?

echo "Create Endorsement Key"
${PREFIX}createendorsementkeypair -v > run.out
checkSuccess $?

echo "OIAP session for Take Ownership"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle $OIAP"

echo "Take Ownership"
${PREFIX}takeownership -pwdo ooo -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo ""
echo "OIAP and OSAP"
echo ""

echo "Start OSAP session using owner auth"
${PREFIX}osap -ha 40000001 -pwd ooo > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "ownersetdisable enable"
${PREFIX}ownersetdisable -en -pwdo ooo -se0 $OSAP 0 -v > run.out
checkSuccess $?

echo "Start OIAP"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle $OIAP"

echo "ownersetdisable enable"
${PREFIX}ownersetdisable -en -pwdo ooo -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo ""
echo "OwnerReadInternalPub"
echo ""

echo "Start OIAP session for owner auth"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP"

echo "Read EK"
${PREFIX}ownerreadinternalpub -ha ek -pwdo ooo -op ekpub.bin -se0 $OIAP 1 -v > run.out
checkSuccess $?

echo "Read SRK"
${PREFIX}ownerreadinternalpub -ha srk -pwdo ooo -op srkpub.bin -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo ""
echo "Quote with AIK"
echo ""

echo "Start OIAP session for SRK auth"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP0=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP0"

echo "Start OSAP for owner auth"
${PREFIX}osap -ha 40000001 -pwd ooo > run.out
checkSuccess $?

OSAP1=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle 1 $OSAP1"

echo "makeidentity -pwdo ooo -ok idkey.bin -op idpub.bin -v -se0 $OIAP0 0 -se1 $OSAP1 0"
${PREFIX}makeidentity -pwdo ooo -ok idkey.bin -op idpub.bin -v -se0 $OIAP0 0 -se1 $OSAP1 0 > run.out
checkSuccess $?

echo "Start OIAP session for SRK auth"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP0=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP0"

echo "loadkey2 -hp 40000000 -ik idkey.bin -se0 $OIAP0 1 -v >! run.out"
${PREFIX}loadkey2 -hp 40000000 -ik idkey.bin -se0 $OIAP0 0 -v > run.out
checkSuccess $?

KEY0=`grep Handle run.out | gawk '{ print $2 }'`
echo "Key handle 0 $KEY0"

echo "Start OSAP for quote key null auth"
${PREFIX}osap -ha $KEY0 > run.out
checkSuccess $?

OSAP0=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle 1 $OSAP0"

echo "quote2 -hk $KEY0 -os sig.bin -ik idkey.bin -se0 $OSAP0 0 -v >! run.out"
${PREFIX}quote2 -hk $KEY0 -os sig.bin -ik idkey.bin -se0 $OSAP0 0 -v > run.out
checkSuccess $?

echo ""
echo "ActivateIdentity"
echo ""

echo "Calculate the EK blob"
${PREFIX}makeekblob -iak idpub.bin -iek ekpub.bin -ob encblob.bin -ok symkey1.bin -v > run.out
checkSuccess $?

echo "Start OIAP session for AIK auth"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP0=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP0"

echo "Start OIAP session for owner auth"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP1=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 1 $OIAP1"

echo "Activate the EK blob"
${PREFIX}activateidentity -ha $KEY0 -pwdo ooo -ib encblob.bin -ok symkey2.bin -se0 $OIAP0 0 -se1 $OIAP1 0 -v > run.out
checkSuccess $?

echo "Verify the recovered key"
diff symkey1.bin symkey2.bin > run.out
checkSuccess $?

echo "Flush key $KEY0"
${PREFIX}flushspecific -ha $KEY0 -rt 1 -v > run.out
checkSuccess $?

echo ""
echo "PCR"
echo ""

echo "Extend PCR 16"
${PREFIX}extend -ha 16 -ic aaa > run.out
checkSuccess $?

echo "Read PCR 16"
${PREFIX}pcrread -ha 16 > run.out
checkSuccess $?

echo ""
echo "NV"
echo ""

echo "Start OSAP session using owner auth"
${PREFIX}osap -ha 40000001 -pwd ooo > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "NV Define Space for EK Certificate - D bit set, must be done before NV lock"
${PREFIX}nvdefinespace -ha 1000f000 -sz 1400 -per 00020002 -v -se0 $OSAP 0 > run.out
checkSuccess $?

echo "Set NV Lock"
${PREFIX}nvdefinespace -ha ffffffff -sz 0 -v > run.out
checkSuccess $?

echo "Start OSAP session using owner auth"
${PREFIX}osap -ha 40000001 -pwd ooo > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "NV Define Space"
${PREFIX}nvdefinespace -ha 10 -sz 20 -pwdn nnn -v -se0 $OSAP 0 > run.out
checkSuccess $?

echo "Start OIAP session"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP"

echo "NV Write"
${PREFIX}nvwritevalueauth -ha 10 -pwdn nnn -if wtmp.txt -se0 $OIAP 1 -v > run.out
checkSuccess $?

echo "NV Read"
${PREFIX}nvreadvalueauth -ha 10 -pwdn nnn -of rtmp.txt -sz 3 -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo "Verify the NV write / read result"
diff wtmp.txt rtmp.txt > run.out
checkSuccess $?

echo "Start OSAP session using owner auth"
${PREFIX}osap -ha 40000001 -pwd ooo > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "NV Undefine space"
${PREFIX}nvdefinespace -ha 10 -sz 0 -v  -se0 $OSAP 0 > run.out
checkSuccess $?

echo ""
echo "EK Certificate Provisioning"
echo ""

echo "Start OIAP session"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle $OIAP"

echo "NV Write with owner auth"
${PREFIX}nvwritevalue -ha 1000f000 -pwdo ooo -if wtmp.txt -se0 $OIAP 1 -v > run.out
checkSuccess $?

echo "NV Read with owner auth"
${PREFIX}nvreadvalue -ha 1000f000 -pwdo ooo -of rtmp.txt -sz 3 -se0 $OIAP 1 -v > run.out
checkSuccess $?

echo "Verify the NV write / read result"
diff wtmp.txt rtmp.txt > run.out
checkSuccess $?

echo "Read EK public key"
${PREFIX}ownerreadinternalpub -ha ek -pwdo ooo -op ekpub.bin -se0 $OIAP 1 -v > run.out
checkSuccess $?

echo "Create the EK Certificate"
${PREFIX}createekcert -pwdo ooo -iek ekpub.bin -of ekcert.der -cakey ../utils/cakey.pem -capwd rrrr -vv > run.out
checkSuccess $?

echo "Read the EK Certificate"
${PREFIX}nvreadvalue -pwdo ooo -ha 1000f000 -cert -of ekcert.der -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo ""
echo "Storage Key"
echo ""

echo "Start OSAP session using SRK auth"
${PREFIX}osap -ha 40000000 > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "Create a child storage key"
${PREFIX}createwrapkey -st -hp 40000000 -pwdk kkk -ok tmpstk.bin -se0 $OSAP 0 -v > run.out
checkSuccess $?

echo "Start OIAP session"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP"

echo "Load the child storage key"
${PREFIX}loadkey2 -hp 40000000 -ik tmpstk.bin -se0 $OIAP 0 -v > run.out
checkSuccess $?

KEYS=`grep Handle run.out | gawk '{ print $2 }'`
echo "Key handle 0 $KEYS"

echo "Start OSAP session using SRK auth"
${PREFIX}osap -ha $KEYS -pwd kkk > run.out
checkSuccess $?

OSAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OSAP handle $OSAP"

echo "Create a child signing key under the child storage key $KEYS"
${PREFIX}createwrapkey -si -hp $KEYS -pwdk sii -ok tmpsik.bin -se0 $OSAP 0 -v > run.out
checkSuccess $?

echo "Start OIAP session"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle 0 $OIAP"

echo "Load the child signing key under the child storage key $KEYS"
${PREFIX}loadkey2 -hp $KEYS -pwdp kkk -ik tmpsik.bin -se0 $OIAP 0 -v > run.out
checkSuccess $?

KEYI=`grep Handle run.out | gawk '{ print $2 }'`
echo "Key handle 0 $KEYI"

echo "Flush child storage key $KEYS"
${PREFIX}flushspecific -ha $KEYS -rt 1 -v > run.out
checkSuccess $?

echo ""
echo "Signing Key"
echo ""

echo "Start OIAP"
${PREFIX}oiap > run.out
checkSuccess $?

OIAP=`grep Handle run.out | gawk '{ print $2 }'`
echo "OIAP handle $OIAP"

echo "Sign and Verify"
${PREFIX}sign -hk $KEYI -pwdk sii -if wtmp.txt -os tmpsig.bin -ik tmpsik.bin -se0 $OIAP 0 -v > run.out
checkSuccess $?

echo "Flush storage key $KEYS"
${PREFIX}flushspecific -ha $KEYI -rt 1 -v > run.out
checkSuccess $?

# cleanup

rm -f wtmp.txt
rm -f rtmp.txt
rm -f idkey.bin
rm -f sig.bin
rm -f ekpub.bin
rm -f srkpub.bin
rm -f idpub.bin
rm -f encblob.bin
rm -f symkey1.bin
rm -f symkey2.bin
rm -f ekcert.der
rm -f tmpstk.bin
rm -f tmpsik.bin
rm -f tmpsig.bin
rm -f run.out

exit
