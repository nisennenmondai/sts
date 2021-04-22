# Secure Telemetry Shell 
MQTT client with end to end encryption for Linux
-------
#### Config file
This is noob level parsing, do not remove space before and after '='
- sts_mode = nosec || master || slave
- qos = 0 || 1 || 2

Those 3 config files use a public MQTT broker, **THERE IS NO PRIVACY PROTECTION**, get it?
- https://www.emqx.io/mqtt/public-mqtt5-broker
- Broker: broker.emqx.io
- TCP Port: 1883

#### HOWTO install
- sudo ./buils.sh 
- cd bin/
- ./sts
- start ../config_nosec

### TODO implement security features
- I want to send encrypted message to a remote client, that includes
  having a key exchange protocole using ECDH **90%**
- I want to support a better AES algorithm than ECB **0%**

### TODO make beautiful tests
- blah blah blah **5%**

### TODO improve mqtt client
- subscribe to multiple topics **0%**
- implement keepalive **0%**

### TODO make beautiful documentation
- howto **1%**
