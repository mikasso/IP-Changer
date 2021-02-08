#!/bin/bash
COUNT=0
INTERFACE_NAME=$1
shift

while (( "$#" )); do 
    NAME=$1
    IP=`dig $NAME +short | tail -n1`
    echo "${NAME} ip is ${IP}"
    if [[ $IP == "" ]]
    then
        echo "Couldn't resolve $NAME. Exit."
        exit
    fi
    ADDRESSES="${ADDRESSES} ${IP}"
    COUNT=$((COUNT+1))
    shift 
done

echo "List of addresses: ${ADDRESSES}"
echo "Count = ${COUNT}"

if (( $COUNT % 2 )); then
    echo "Need one more domain name to redirect ip addresses. Exit."
    exit
fi

echo "./LoadModule.sh $COUNT ${ADDRESSES:1} $INTERFACE_NAME"
./LoadModule.sh ${COUNT} "${ADDRESSES:1}" ${INTERFACE_NAME}
