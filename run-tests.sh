#!/bin/sh
cd tests/ecdh_aes_cbc_256/
./ecdh_aes_cbc_256
echo ""

cd ../ecdh_aes_ecb_256/
./ecdh_aes_ecb_256
echo ""

cd ../mqtt/
./tests_mqtt

cd ../sha256/
./sha256
echo ""
