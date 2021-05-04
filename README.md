# **Secure Telemetry Shell**
## *MQTT client with end to end encryption for Embedded Linux*

## **Features**

- **Lightweight MQTT client** for Embedded Linux
- **Authentication** scheme
- **End-to-End Encryption** with dynamic cryptographic key generation at each session
- **Encapsulation** in shell

## **Introduction**

STS is an application-layer protocol on top of MQTT that allows payload end-to-end encryption between 2 clients. You can find more information about MQTT payload encryption on this link: https://www.hivemq.com/blog/mqtt-security-fundamentals-payload-encryption/
This can be very useful as MQTT-TLS does not provide end-to-end encryption between 2 clients and often cannot be implemented on resource constraints systems such as MCU.

## **Dependencies**

STS uses a number of open source projects to work properly:

- [paho-mqtt-embedded-c](https://github.com/eclipse/paho.mqtt.embedded-c) - Eclipse Paho MQTT C/C++ client for Embedded platforms
- [mbedtls](https://github.com/ARMmbed/mbedtls) - Mbed TLS is a C library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols.

## **Installation**

STS is standalone and should work with any Linux distrib.

```sh
./build
```

## **HOWTO**
STS can be used in 2 modes: with or without encryption: 
**No encryption** means a simple MQTT client with minimal features like subscribing to a topic and publishing message. I believe there is no need to go for STS for that kind of use and so this part will not be improved.

**With encryption** means that you can send encrypted messages to an other client, nothing aside of those can decrypt the data and that's the all point. STS can be useful if you have no way to use MQTT-TLS in your project.

##### MQTT features that aren't implemented are:
- Quality Of Service
- Keep Alive
- Persistent session
- Multiple subscriptions per client

#### Configuration files
STS needs to use configuration files, those contain parameters for MQTT and STS, the ones provided work just fine, they use a public broker: https://www.hivemq.com/public-mqtt-broker/

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

#### Simple MQTT Client
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
![](https://lh3.googleusercontent.com/pw/ACtC-3fWJpidfDiD1YTF5LUdR-51SwG6BRr_YcKd6ElosGafl6gYFAeVu0qoy1yRmqryBqbBDj8-31Op2_OeXn4s5Kw0zs4QCAmshudjTaIGmHzqw8oKudgPrWBjhOGh8X5V50clinjO1-sLYNVx8rMnQCby=w797-h234-no?authuser=0)
#### MQTT Client with end-to-end encryption
You need to launch 2 clients for this, one in *slave mode* and the other in *master mode*. Protocol is designed as so you need to launch *Slave* first then *Master*
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
![](https://lh3.googleusercontent.com/pw/ACtC-3ddcT_Ipsya29gPxqzpz5gUP-It-0Idc71cGCQ_8fxYWjNMR-nCiypmxKSkqGMgBvvO4A8qAieMYwap0i6gpb8-rVuy2Vg-G2ZDnishYSccI7mBIOi9D0XTaQfSg6rM3gmCLunG6ovq1kTqvDHf7gAJ=w1918-h578-no?authuser=0)

## **Protocol Architecture**
#### STS message
STS uses MQTT so a STS message is encapsulated in a MQTT message. It has one header which contains the message type and a payload. Total size of a STS message is the same as MQTT, in this implementation it is set to 1024 bytes:
**[--HEADER--][--DATA--]**

#### message types
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

#### Authentication
