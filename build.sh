#!/bin/sh
git submodule update --init --recursive

#paho
cd lib/paho-mqtt
cmake .
make
cd ../../

#mbed
cd lib/mbedtls/
cmake .
make
cd ../../

#sts
make
