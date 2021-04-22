# Secure Telemetry Shell 
MQTT client with end to end encryption for Linux
-------
#### Config file
This is noob level parsing, do not remove space before and after '='. Config
files provided work just fine.
- sts_mode = nosec || master || slave
- qos = 0 || 1 || 2

Those 3 config files use a public MQTT broker, **THERE IS NO PRIVACY PROTECTION**, get it?
- https://www.emqx.io/mqtt/public-mqtt5-broker
- Broker: broker.emqx.io
- TCP Port: 1883

#### HOWTO install
- sudo ./buils.sh 
- cd bin/

#### HOWTO use as a simple mqtt client
- ./sts
- start ../config_nosec_1 (sts_mode = nosec)
- send [your message even with space]

#### HOWTO use with end-to-end encryption with an other client
- ./sts
- start ../config_slave (you need to launch slave first!)
- start ../config_master (now wait for session to be established, it is possible
  that computation of shared secret fails in this case restart both clients)
- sendenc [your encrypted message even with space]

### TODO improve security features
- I want to support a better AES algorithm than ECB **0%**

### TODO make beautiful tests
- blah blah blah **5%**

### TODO make beautiful documentation
- howto with example **1%**
