# **Secure Telemetry Shell**
## *MQTT client with End-to-End Payload Encryption for Embedded Linux*

## **Features**

- **Lightweight MQTT client** for Embedded Linux
- **Authentication** scheme
- **End-to-End Payload Encryption** with symmetric cipher
- **Encapsulation** in a shell for easy of use and possible modules development

## **Introduction**

STS is an application-layer protocol on top of MQTT that allows payload E2EE. 
You can find more information about MQTT payload encryption on this link:

https://www.hivemq.com/blog/mqtt-security-fundamentals-payload-encryption/

### **When to use STS?**
- TLS is not available
- Dealing with untrusted broker
- Use of constrained devices
- Need for secure E2EE of application data
- Need for an additional layer of security working in conjunction with TLS

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
subscribing to a topic and publishing messages. I believe there is no need to go 
for STS for that kind of use and so this part will not be improved.

**With encryption** means that you can send encrypted messages to an other 
client, nothing aside of those can decrypt the data and that's the all point. 

**MQTT features that aren't implemented are:**
- Quality Of Service
- Keep Alive
- Persistent session
- Multiple subscriptions per client

### Configuration files
STS needs to use configuration files, those contain parameters for MQTT and STS, 
the ones provided work just fine, they use a public broker: 

https://www.emqx.io/mqtt/public-mqtt5-broker

If can't connect try this one:

https://www.hivemq.com/public-mqtt-broker/

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

### STS no encryption
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
### STS with encryption
2 clients are needed, one in *slave mode* and the other in *master mode*. 
Protocol is designed as so you need to start a session with *slave* first then 
with *master*.
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
### STS Message
STS uses MQTT so a STS message is encapsulated in a MQTT message. It has one 
*header* which contains the message type and a *data*. Total size of a STS 
message is the same as MQTT, in this implementation it is set to 1024 bytes:
**[--HEADER--][--DATA--]**

### Message Types
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
*master* generates 2 IDs 32 bytes long based on ASCII table and sends 
**INITREQ** to *slave*, during authentication all data is *obfuscated*. 
Obfuscated, so they aren't human readable, algorithm used in this implementation 
is:

*obfuscation* [reverse_bits_order -> xor]

*clarification* [xor -> reverse_bits_order]

This is a very simple way of obfuscating data and only serves as an example, it 
is highly recommended that user has his own very **PRIVATE** algorithm for 
obfuscation to avoid usurpation attack. *slave* acknowledges sending **INITACK**
, now *master* proceeds to send **AUTHREQ** attaching *slave*'s ID, upon receipt 
*slave* will verify if ID matches and authenticate *master* sending **AUTHACK**, 
if not it will standby and not return anything until timer is up. It is then 
*slave*'s turn to send **AUTHREQ**, once *master* verifies if ID matches it will 
acknowledge with **AUTHACK**. From now on both clients are authenticated and can
proceed to cryptographic keys exchange.

### Key Exchange and Shared Secret
Once authentication phase is done *master* sends **RDYREQ** with its public key, 
upon receipt *slave* computes the shared secret and acknowledges with 
**RDYACK**. Now it is *slave*'s turn to send his public key with **RDYREQ**,
upon receipt *master* computes the shared secret and acknowledges with 
**RDYACK**. At this point encrypted communication is available and every message 
will be sent with an **ENC** header.

### Deconnection
If any of the two clients ends its session a **KILL** message is sent to 
the remote client to notify it to terminate its session too.

### Algorithms
Key exchange agreement protocol used is **ECDH**, elliptic curve is 
**SECP256K1,** finally encryption used is **AES**, 2 block cipher modes 
operation are available, **ECB** and **CBC**, I don't see any reason to use ECB 
over CBC as it leaks information with obvious pattern on repeating data. 
Regarding CBC in this implementation initialization vector is static for the 
session, it uses the computed shared secret.
