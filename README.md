# Secure Telemetry Shell 
MQTT client with end to end encryption for embedded Linux
-------

TODO

1 - IMPROVE CLIENT
- I want to send message containing "space" (those aren't command anymore!)
- I want to connect to a broker entering parameters manually.
- I want to be able to save parameters of broker in a config file and load them
  that includes sub and pub topic.
- I want the status command to display more information about the security.
- I want to move the keygeneration to encrypted mode only. So it should not be 
  by default.

2 - IMPLEMENT SECURITY FEATURES
- I want to be able to send encrypted message to a remote client, that includes
  having a key exchange protocole.
- I want to have an encrypted mode and non encrypted mode.
- I want to support a better AES algorithm than ECB

