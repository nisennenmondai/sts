# Secure Telemetry Shell 
MQTT client with end to end encryption for embedded Linux
-------
#### Regarding config file
Check "template_config", this is noob level parsing, do not remove space before and after '='
- [key] = [value] ---> ip = 66.66.66.66
- [value] max size in char: 64

#### How to use
- cd bin/
- ./sts
- start ../path_to_your_config_file

#### TODO implement security features
- I want to be able to send encrypted message to a remote client, that includes
  having a key exchange protocole using ECDH
- I want to have digital signature using ECDSA
- I want to support a better AES algorithm than ECB

