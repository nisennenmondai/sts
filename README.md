# Secure Telemetry Shell 
MQTT client with end to end encryption for Embedded Linux
-------
#### CONFIG files
Config files provided work just fine.
- qos           = 0 || 1 || 2
- is_retained   = 0 || 1
- clean_session = 0 || 1
- sts_mode      = nosec || master || slave

Those config files use a public MQTT broker, **THERE IS NO PRIVACY PROTECTION**
- https://www.emqx.io/mqtt/public-mqtt5-broker
- Broker: broker.emqx.io
- TCP Port: 1883

#### HOWTO build
- ./buils.sh 

#### HOWTO use as a simple mqtt client
- **cd** bin/
- ./sts
- **start** ../config_nosec (sts_mode = nosec)
- **send** [your message]

#### HOWTO use as a mqtt client with end-to-end encryption with an other client
Slave side (launch slave first)
- **cd** bin/
- ./sts
- **start** ../config_secslave

Master side
- **cd** bin/
- ./sts
- **start** ../config_secmaster (wait for encryption to be established)
- **sendenc** [your soon to be encrypted message]

### STS Protocole Architecture
Soon to be done...

### TODO improve security features
- I want to support a better AES algorithm than ECB (CBC) **0%**
- I want to authentify clients with auto generated ID at each session **0%**
- Nice to have: I want to have digital signature with ECDSA **0**
- Nice to have: I want to have debug level **0%**

### TODO make beautiful tests
- I want to have beautiful tests (mqtt, sts, security) **5%**

### TODO make beautiful documentation
- I want to have a beautiful README.md **1%**
