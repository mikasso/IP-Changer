#!/bin/bash
NAME="addresses_replacer"
sudo rmmod $NAME
sudo dmesg -C
cd ./module
make
sudo insmod ./$NAME.ko addr_count=$1 addr=\"$2\" interface_name=\"$3\"
sudo dmesg
