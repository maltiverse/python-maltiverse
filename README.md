![](https://maltiverse.com/assets/images/logo/logo_letters_black.png)

# python-maltiverse
Python library for [maltiverse.com](https://www.maltiverse.com/) API.

This python package is meant to ease request to the Maltiverse IoC search engine API which formal definition can be found here:

https://app.swaggerhub.com/apis-docs/maltiverse/api/1.0.0-oas3



## [1 - Installation](#table-of-contents)

```
pip install git+https://github.com/maltiverse/python-maltiverse
```


## [2 - Usage](#table-of-contents)

## [2.1 - Authentication](#table-of-contents)

Authentication in maltiverse follows a http bearer model with JWT token. JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.

We can create a Maltiverse account in the website and use those credentials to login 

```
from maltiverse import Maltiverse
api = Maltiverse()
api.login(email="email", password="password")
```

From this point request will be sent with authentication JWT parameter if required.


+ ip_get()
+ hostname_get()
+ url_get()
+ sample_get()




## [2.2 - IPv4](#table-of-contents)
## [2.2.1 - GET](#table-of-contents)
   
   




## Examples

Without API authentication:

```
from maltiverse import Maltiverse
api = Maltiverse()
api.hostname_get('teske.pornicarke.com')
```

With API authentication:

```
from maltiverse import Maltiverse
api = Maltiverse()
api.login(email="email", password="password")
api.hostname_get('teske.pornicarke.com')
```

## Output

```  
{
  "as_name": "AS1741 Tieteen tietotekniikan keskus Oy",
  "blacklist": [
    {
      "description": "Worm.FFAuto",
      "last_seen": "2017-10-08 17:01:05",
      "source": "Maltiverse"
    }
  ],
  "dnssec": "unsigned",
  "domain": "teske.pornicarke.com",
  "emails": "abuse@godaddy.com",
  "last_updated": "2014-04-25 11:05:20",
  "name_servers": [
    "PDNS03.DOMAINCONTROL.COM",
    "PDNS04.DOMAINCONTROL.COM"
  ],
  "org": "Fitsec Ltd",
  "registrant_name": "GoDaddy.com, LLC",
  "resolved_ip": [
    {
      "ip_addr": "193.166.255.171",
      "timestamp": "2017-10-08 17:01:05"
    }
  ],
  "status": [
    "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
    "clientRenewProhibited https://icann.org/epp#clientRenewProhibited",
    "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited"
  ],
  "tag": [
    "botnet",
    "p2p",
    "palevo",
    "worm"
  ],
  "timestamp": "2017-10-08 17:01:05",
  "whois_server": "whois.godaddy.com"
}
```

