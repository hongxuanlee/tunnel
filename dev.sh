#!/bin/bash

cd `dirname $0`

make build

sudo pkill output
pushd ..
sudo ./packets/output &
popd

echo "Start packets_capture success."

PID=$!

echo "process pid is $!"

trap 'killChild' INT

killChild() {
    trap '' INT TERM
    echo "**** Shutting down... ****"     # added double quotes
    sudo kill $PID
    echo DONE
}

wait $PID
