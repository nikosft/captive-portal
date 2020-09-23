# A captive portal that uses IPTABLES

## Introduction
This is a very simple captive portal that uses IPTABLES and python's BaseHTTPServer.
When it is executed it blocks all traffic except DNS and redirects all HTTP
traffic to a login page. When a user enters the correct credentials a new 
IPTABLES entry is added and all the traffic originating from the IP address
of that user is allowed.
## Using it
It is highly recommended to flush IPTABLES before using this scipt. You
can do that using the following commands

```
$ sudo iptables -F
$ sudo iptables -t nat -F
```

Modify the `PORT`, `IFACE`, and `IP_ADDRESS` variables according to your needs.
Moreover, if you plan to use this code for something more than proof of concept
make user you modify the `dummy security check` at line 69 of the script.

Run the script with su priviledges. The username and the password used in the
provided script are `nikos` and `fotiou` respectively.
