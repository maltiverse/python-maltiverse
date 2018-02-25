# maltiverse-python
Python library for [maltiverse.com](https://www.maltiverse.com/) APIs

## Install

```
pip install git+https://github.com/maltiverse/python-maltiverse
```

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

## Available methods

+ ip_get()
+ hostname_get()
+ url_get()
+ sample_get()
