# ezovpn - .ovpn files import/generation tool

The simple tool that allows importing and generation of OpenVPN configuration files with **embedded certificates**, as this is the format
that you might want to use for OpenVPN client on Android or iPhone.

OpenVPN allows to include CA/Certificate/Key/TlsAuth files right into the OpenVPN configuration file. 
For example:
```
client
dev tun
proto udp
remote 1.2.3.4 1141
nobind
persist-key
persist-tun
key-direction 1
comp-lzo
 
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
<cert>

...
</cert>
 
<key>
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
</key>

<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
...
-----END OpenVPN Static key V1-----
</tls-auth>
```

In a way it means simply replacing the configuration lines:
```
ca /etc/openvpn/ca.crt
cert /etc/openvpn/client.crt
key /etc/openvpn/client.key
tls-auth /etc/openvpn/ta.key 1
```
with the content of the corresponding files.

This application makes it easier either to generate the new basic OpenVPN configuration with all the necessary resources, or to import and convert the existing OpenVPN configuration.

```
Usage:
   [flags]
   [command]

Available Commands:
  generate    Generates the config file according to the built-in template
  help        Help about any command
  import      Imports an existing VPN configuration and embeds the certificates

Flags:
  -d, --confdir string   VPN root dir to look for certificates
  -h, --help             help for this command
  -o, --out string       .ovpn config file ( if not specified - then stdout will be used )

Use " [command] --help" for more information about a command.
```

### Generate

If you have the certificates and keys generated by [easy-rsa](https://github.com/OpenVPN/easy-rsa) and just want to generate bare minimum OpenVPN configuration file:

```
ezovpn generate -h
Generates the config file according to the built-in template

Usage:
   generate [flags]

Aliases:
  generate, gen

Flags:
      --ca string       RSA CA file name (default "ca.crt")
      --cert string     RSA certificate file name
  -h, --help            help for generate
      --key string      RSA certificate key file name
  -p, --port int        VPN Port (default 1144)
  -s, --server string   VPN Server
      --ta string       VPN tls-auth key file name (default "ta.key")

Global Flags:
  -d, --confdir string   VPN root dir to look for certificates
  -o, --out string       .ovpn config file ( if not specified - then stdout will be used )
```

Example run would be something like:
```
ezovpn -d /etc/openvpn gen --cert client.crt --key client.key -s 123.123.123.123
```

### Import

If you have a config file you want to embed the certificates into:
```
ezovpn import -h
Imports an existing VPN configuration and embeds the certificates

Usage:
   import [flags]

Aliases:
  import, imp

Flags:
  -h, --help            help for import
  -i, --import string   VPN configuration file ( if not specified - stdin will be used )

Global Flags:
  -d, --confdir string   VPN root dir to look for certificates
  -o, --out string       .ovpn config file ( if not specified - then stdout will be used )
```
and the example command line would be:
```
ezovpn -d /etc/openvpn import -i /etc/openvpn/client.conf
```

## Note

Doesn't work with PKCS12 bundles at the moment.