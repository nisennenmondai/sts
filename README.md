# Secure Telemetry Shell 
MQTT client with end to end encryption for Embedded Linux
-------
#### CONFIG file
This is noob level parsing, do not remove space before and after '='. Config
files provided work just fine.
- qos           = 0 || 1 || 2
- is_retained   = 0 || 1
- clean_session = 0 || 1
- sts_mode      = nosec || master || slave

Those config files use a public MQTT broker, **THERE IS NO PRIVACY PROTECTION**, get it?
- https://www.emqx.io/mqtt/public-mqtt5-broker
- Broker: broker.emqx.io
- TCP Port: 1883

#### HOWTO build
- ./buils.sh 

#### HOWTO use as a simple mqtt client
- **cd** bin/
- ./sts
- **start** ../config_nosec_1 (sts_mode = nosec)
- **send** [your message even with space]

#### HOWTO use with end-to-end encryption with an other client
Slave side (launch slave first)
- **cd** bin/
- ./sts
- **start** ../config_secslave

Master side
- **cd** bin/
- ./sts
- **start** ../config_secmaster (wait for encryption to be established)
- **sendenc** [your soon to be encrypted message even with space]

### STS Protocole Architecture
Soon to be done...

### TODO improve security features
- I want to support a better AES algorithm than ECB **0%**

### TODO make beautiful tests
- blah blah blah **5%**

### TODO make beautiful documentation
- howto with beautiful pictures **1%**
