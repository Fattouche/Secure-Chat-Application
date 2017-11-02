# Secure-Chat-Client
This is a java chat application that implements encryption, signing and authorization.

Authorization:
client password: clientPass **case sensitive
server password: serverPass **case sensitive

Signing:
Using AES we have message authentication codes

encryption:
We establish AES keys using Diffie helmen key establishment protocol, messages are then encrypted using AES.
