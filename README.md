# **Secure Telemetry Shell**
## *MQTT client with End-to-End Payload Encryption for Embedded Linux*

## **Features**

- **Lightweight MQTT client** for Embedded Linux
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
- Need for an additional layer of security working in addition with TLS

    ![](doc/img/archi.png?raw=true "stack")

## **Dependencies**

STS uses a number of open source projects to work properly:

- [paho-mqtt-embedded-c](https://github.com/eclipse/paho.mqtt.embedded-c) - 
    Eclipse Paho MQTT C/C++ client for Embedded platforms
- [mbedtls](https://github.com/ARMmbed/mbedtls) - Mbed TLS is a C library that 
    implements cryptographic primitives, X.509 certificate manipulation and the 
    SSL/TLS and DTLS protocols.

```sh
sudo apt install cmake g++
```

## **Installation**

```sh
make deps
make
```
- **make deps** will download and build *paho-mqtt* and *mbedtls*
- **make** will build *sts*

## **Tests**

```sh
make build-tests
make run-tests
```
- **make build-tests** will build tests
- **make run-tests** will run tests

## **HOWTO**
STS can be used in 2 modes: with or without encryption: 
**No encryption** means a simple MQTT client with minimal features like 
subscribing to a topic and publishing messages. 

**With encryption** means that an end-2-end encrypted communication is
established

**MQTT features that aren't implemented are:**
- Quality Of Service
- Keep Alive
- Persistent session
- Multiple subscriptions per client

### Configuration files
STS needs to use configuration files, those contain parameters for MQTT and STS, 
the ones provided work just fine, it uses a public broker: 

**broker.hivemq.com**

It is also possible to test it in local using mosquitto, launch a mosquitto broker
and simply add "localhost" to the url field.

| KEY  | VALUE (128 char max)| 
| ------------- | ------------- |
| **url**  | broker url  |
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
start ../configs/nosec
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
start ../configs/secslave
```
```sh
start ../configs/secmaster
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
| **KEYREQ**  | Key request |
| **KEYACK**  | Key acknowledgement  |
| **ENC**  | Encrypted message  |
| **KILL**  | Message that tells remote client to terminate its session  |

### Connection Protocol
![Alt text](doc/img/connection_protocol.png?raw=true "conn")

### Key Exchange and Shared Secret
*master* sends **KEYREQ** with its public key, upon receipt *slave* computes the 
shared secret and acknowledges with **KEYACK**. Now it is *slave*'s turn to send 
its public key with **KEYREQ**, upon receipt *master* computes the shared secret 
and acknowledges with **KEYACK**. At this point encrypted communication is 
available and every message will be sent with an **ENC** header.

### Disconnection
If any of the two clients ends its session a **KILL** message is sent to 
the remote client to notify it to terminate its session too.

### Algorithms
Key exchange agreement protocol used is **ECDH**, elliptic curve is 
**SECP256K1,** finally encryption used is **AES-256**, 2 block cipher modes 
operation are available, **ECB** and **CBC**.

### TODO
- maybe sequence number on msg?
- maybe msg integrity with SHA256?
- and maybe digital signature with ECDSA?
