#!/bin/bash

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
    exit 255
else
    echo " INFO:"
fi
}

./reg.sh -0

echo ""
echo "Sign with restricted HMAC key"
echo ""

# for HALG in ${ITERATE_ALGS}

#do

    echo "Create a ${HALG} restricted keyed hash key under the primary key"
    ${PREFIX}create -hp 80000000 -khr -kt f -kt p -opr khrprivsha256.bin -opu khrpubsha256.bin -pwdp sto -pwdk khk -halg sha256 > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr  khrprivsha256.bin -ipu khrpubsha256.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Hash and create ticket"
    ${PREFIX}hash -hi p -halg sha256 -if msg.bin -oh sig.bin -tk tkt.bin > run.out
    checkSuccess $?

    echo "Sign a digest with a restricted signing key and ticket"
    ${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk khk > run.out
    checkSuccess $?



#done


