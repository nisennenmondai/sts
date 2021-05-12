# **Secure Telemetry Shell**
## *MQTT client with End-to-End Payload Encryption for Embedded Linux*

## **Features**

- **Lightweight MQTT client** for Embedded Linux
- **Authentication** scheme
- **End-to-End Payload Encryption** with symmetric cipher
- **Encapsulation** in a shell

## **Introduction**

STS is an application-layer protocol on top of MQTT that allows payload 
end-to-end encryption between 2 clients. You can find more information about 
MQTT payload encryption on this link:

https://www.hivemq.com/blog/mqtt-security-fundamentals-payload-encryption/

This can be very useful as MQTT-TLS does not provide "true" E2EE and sometimes 
cannot be implemented on resource constraints systems such as MCU.

![](doc/img/archi.png?raw=true "stack")

## **Dependencies**

STS uses a number of open source projects to work properly:

- [paho-mqtt-embedded-c](https://github.com/eclipse/paho.mqtt.embedded-c) - 
    Eclipse Paho MQTT C/C++ client for Embedded platforms
- [mbedtls](https://github.com/ARMmbed/mbedtls) - Mbed TLS is a C library that 
    implements cryptographic primitives, X.509 certificate manipulation and the 
    SSL/TLS and DTLS protocols.

## **Installation**

STS is standalone and should work with any Linux distrib.

```sh
./build
```

## **HOWTO**
STS can be used in 2 modes: with or without encryption: 
**No encryption** means a simple MQTT client with minimal features like 
subscribing to a topic and publishing message. I believe there is no need to go 
for STS for that kind of use and so this part will not be improved.

**With encryption** means that you can send encrypted messages to an other 
client, nothing aside of those can decrypt the data and that's the all point. 
STS can be useful if you have no way to use MQTT-TLS in your project.

**MQTT features that aren't implemented are:**
- Quality Of Service
- Keep Alive
- Persistent session
- Multiple subscriptions per client

### Configuration files
STS needs to use configuration files, those contain parameters for MQTT and STS, 
the ones provided work just fine, they use a public broker: 

https://www.hivemq.com/public-mqtt-broker/

If can't connect try this one:

https://www.emqx.io/mqtt/public-mqtt5-broker


| KEY  | VALUE (128 char max)| 
| ------------- | ------------- |
| **mqtt_version** | 3 or 4  |
| **ip**  | broker ip  |
| **port**  | usually 1883 for TCP  |
| **username**  | if broker requires login  |
| **password**  | if broker requires login  |
| **subtop**  | topic to subscribe  |
| **pubtop**  | topic to publish  |
| **clientid**  | mqtt id  |
| **sts_mode**  | nosec, master, slave  |
| **aes**  | null, ecb, cbc  |

### Simple MQTT Client
Launch STS
```sh
cd bin/
./sts
```
Start a session and send messages
```sh
start ../config_nosec
send my message
```
Stop a session
```sh
stop
```
![](doc/img/nosec.png?raw=true "nosec")
### MQTT Client with end-to-end encryption
You need to launch 2 clients for this, one in *slave mode* and the other in 
*master mode*. Protocol is designed as so you need to launch *Slave* first then 
*Master*
```sh
start ../config_secslave
```
```sh
start ../config_secmaster
```
Once encryption is established you can send encrypted message with:
```sh
sendenc my message
```
![](doc/img/sec.png?raw=true "sec")

## **Architecture**
### STS message
STS uses MQTT so a STS message is encapsulated in a MQTT message. It has one 
header which contains the message type and a payload. Total size of a STS 
message is the same as MQTT, in this implementation it is set to 1024 bytes:
**[--HEADER--][--DATA--]**

### message types
|   | | 
| ------------- | ------------- |
| **INITREQ** | Initialization request |
| **INITACK**  | Initialization acknowledgement |
| **AUTHREQ**  | Authentication request |
| **AUTHACK**  | Authentication acknowledgement  |
| **RDYREQ**  | Ready request, ask if remote client is ready for encrypted communication |
| **RDYACK**  | Ready acknowledgement  |
| **ENC**  | Encrypted message  |
| **KILL**  | Message that tells remote client to terminate its session  |

### Connection Protocol
![Alt text](doc/img/connection_protocol.png?raw=true "conn")

### Authentication
Master client generates 2 ids 32 char long based on ASCII table, during 
authentication those ids are *obfuscated* and sent with **INITREQ** to Slave. 
Obfuscated, so they aren't human readable, algorithm used in this implementation 
is:

*obfuscation* [reverse_bits_order -> xor]

*clarification* [xor -> reverse_bits_order]

This is a very simple way of obfuscating data and only serves as an example, it 
is highly recommended that user has his own very **PRIVATE** algorithm for 
obfuscation. Slave will then acknowledge with **INITACK**. Master then sends 
obfuscated **AUTHREQ** with id_slave (could be the other way around with 
id_master) so Slave can verify it and authenticate Master. Slave acknowledges 
with **AUTHACK** and do the same with AUTHREQ, once Master verifies its received 
id_master, authentication of both clients is done.

### Encryption
After authentication Master will send **RDYREQ** with its public key to Slave,
this one will proceed to compute the shared secret and reply with **RDYACK** + 
its public key. Master receives Slave's public key, compute the shared secret 
and reply with RDYACK. From this point encrypted communication is available and
every message will be sent with the **ENC** header.

Key exchange agreement protocol used is **ECDH**, elliptic curve is 
**SECP256K1,** finally encryption used is **AES**, 2 block cipher modes 
operation are available, **ECB** and **CBC**, I don't see any reason to use ECB 
over CBC as it leaks information with obvious pattern on repeating data. 
Regarding CBC in this implementation initialization vector is static for the 
session, it uses the computed shared secret.

### Deconnection
If any of the two clients ends its session a **KILL** message will be sent to 
the remote to notify it to end its session too.

## TODO in the near/far/very far/ future...
- Digital signature
