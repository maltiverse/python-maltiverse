![](https://maltiverse.com/assets/images/logo/logo_letters_black.png)

# python-maltiverse
Python library for [maltiverse.com](https://www.maltiverse.com/) API.

This python package is meant to ease request to the Maltiverse IoC search engine API which formal definition can be found here:

https://app.swaggerhub.com/apis-docs/maltiverse/api/1.0.0-oas3



## [1 - Installation](#table-of-contents)

```
pip install maltiverse
```


## [2 - Usage](#table-of-contents)

## [2.1 - Authentication](#table-of-contents)

Authentication in maltiverse follows a OAuth 2.0 http bearer model with JWT token. JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.

We can create a Maltiverse account in the website and use those credentials to login like this:

```python
from maltiverse import Maltiverse
api = Maltiverse()
api.login(email="email", password="password")
```

Alternatively Maltiverse provides a permanent API Key that is required for some scenarios. This API Key can be generated in profile page once registered by clicking "Generate API Key" button. Copy your API key and pass it to the constructor with parameter auth_token

```python
from maltiverse import Maltiverse
api = Maltiverse(auth_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAzZSBSZXNlYXJjaCBUZWFtIiwi")
```

From this point request will be sent with authentication JWT parameter if required.


+ ip_get()
+ hostname_get()
+ url_get()
+ sample_get()




## [2.2 - IPv4](#table-of-contents)
## [2.2.1 - GET](#table-of-contents)

Retrieves an IPv4 address in JSON format

```python
import json
from maltiverse import Maltiverse
api = Maltiverse()

result = api.ip_get("110.189.222.98")
print(json.dumps(result, indent=4, sort_keys=True))
```

Output
```json
{
    "address": "No.31 ,jingrong street,beijing\n100032",
    "as_name": "AS4134 Chinanet",
    "asn_cidr": "110.184.0.0/13",
    "asn_country_code": "CN",
    "asn_date": "2009-05-11 00:00:00",
    "asn_registry": "apnic",
    "blacklist": [
        {
            "count": 1,
            "description": "Mail Spammer",
            "first_seen": "2017-11-30 12:39:45",
            "last_seen": "2017-11-30 12:39:45",
            "source": "Blocklist.de"
        },
        {
            "count": 1,
            "description": "Malicious Host",
            "first_seen": "2020-01-28 00:45:48",
            "last_seen": "2020-01-29 07:10:12",
            "source": "CIArmy"
        },
        {
            "count": 1,
            "description": "Malicious Host",
            "first_seen": "2020-01-29 00:18:08",
            "last_seen": "2020-02-19 06:34:10",
            "source": "Alienvault Ip Reputation Database"
        },
        {
            "count": 1,
            "description": "Mail Spammer",
            "first_seen": "2020-03-22 11:18:35",
            "last_seen": "2020-03-22 11:18:35",
            "source": "Barracuda"
        },
        {
            "count": 5,
            "description": "Scanning IPs",
            "first_seen": "2020-01-26 09:01:00",
            "last_seen": "2020-02-01 10:26:00",
            "source": "IBM X-Force Exchange"
        },
        {
            "count": 32,
            "description": "Spam",
            "first_seen": "2017-07-14 06:44:00",
            "last_seen": "2020-03-21 07:52:00",
            "source": "IBM X-Force Exchange"
        }
    ],
    "cidr": [
        "110.184.0.0/13"
    ],
    "classification": "malicious",
    "country_code": "CN",
    "creation_time": "2017-11-30 12:39:45",
    "email": [
        "anti-spam@ns.chinanet.cn.net",
        "scipadmin2013@189.cn"
    ],
    "ip_addr": "110.189.222.98",
    "location": {
        "lat": 30.6667,
        "lon": 104.0667
    },
    "modification_time": "2020-02-19 06:34:10",
    "registrant_name": "CHINANET Sichuan province network\nData Communication Division\nChina Telecom",
    "tag": [
        "mail",
        "spam"
    ],
    "type": "ip"
}
```

## [2.3 - Hostname](#table-of-contents)
## [2.3.1 - GET](#table-of-contents)

Retrieves a Hostname in JSON format

```python
import json
from maltiverse import Maltiverse
api = Maltiverse()

result = api.hostname_get("59022.flatblastard.com")
print(json.dumps(result, indent=4, sort_keys=True))
```

Output
```json
{
    "as_name": "AS47142 PP Andrey Kiselev",
    "blacklist": [
        {
            "count": 1,
            "description": "Ponmocup",
            "first_seen": "2020-03-22 08:14:16",
            "last_seen": "2020-03-22 08:14:16",
            "source": "Dyndns.org"
        }
    ],
    "classification": "malicious",
    "creation_time": "2020-03-22 08:14:17",
    "domain": "flatblastard.com",
    "domain_consonants": 11,
    "domain_lenght": 22,
    "entropy": 3.8796640049025934,
    "hostname": "59022.flatblastard.com",
    "modification_time": "2020-03-22 08:14:17",
    "resolved_ip": [
        {
            "ip_addr": "91.207.4.51",
            "timestamp": "2020-03-22 08:14:17"
        },
        {
            "ip_addr": "184.168.131.241",
            "timestamp": "2019-12-05 10:08:14"
        },
        {
            "ip_addr": "50.63.202.16",
            "timestamp": "2018-11-21 07:43:52"
        }
    ],
    "tag": [
        "ponmocup",
        "malware"
    ],
    "tld": "com",
    "type": "hostname"
}
```
