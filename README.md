# Secure Telemetry Shell 
MQTT client with end to end encryption for Embedded Linux
-------
#### CONFIG files
Config files provided work just fine.
- mqtt_version = 3 || 4
- sts_mode = nosec || master || slave
- aes = null || ecb || cbc

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

### TODO make beautiful tests
- I want to have beautiful tests (mqtt, sts, security) **40%**

### TODO make beautiful documentation
- I want to have a beautiful README.md **1%**
