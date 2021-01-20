#!/bin/sh
git submodule update --init --recursive

#paho
cd lib/paho-mqtt
cmake .
make
make install
cd ../../

#mbed
cd lib/mbedtls/
cmake .
make
make install
cd ../../

#sts
make
