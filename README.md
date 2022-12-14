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


## [2.4 - Url](#table-of-contents)
## [2.4.1 - GET](#table-of-contents)

Retrieves a URL in JSON format

```python
import json
from maltiverse import Maltiverse
api = Maltiverse()

result = api.url_get("https://alleom.com/weqmo")
print(json.dumps(result, indent=4, sort_keys=True))
```

Output
```json
{
    "blacklist": [
        {
            "count": 1,
            "description": "Phishing Other",
            "first_seen": "2020-03-22 08:53:10",
            "last_seen": "2020-03-22 08:53:10",
            "source": "Phishtank"
        },
        {
            "count": 1,
            "description": "Social Engineering",
            "first_seen": "2020-03-22 08:53:10",
            "labels": [
                "malicious-activity"
            ],
            "last_seen": "2020-03-22 08:53:10",
            "source": "Google Safebrowsing"
        }
    ],
    "classification": "malicious",
    "creation_time": "2020-03-22 08:53:10",
    "domain": "alleom.com",
    "hostname": "alleom.com",
    "modification_time": "2020-03-22 08:53:10",
    "tag": [
        "phishing"
    ],
    "tld": "com",
    "type": "url",
    "url": "https://alleom.com/weqmo",
    "urlchecksum": "7b0ef6e5d95e2ee2c2602135c39f3fe09fe8f1eee7f5769266a0dbe718696ec3"
}
```


## [2.5 - Sample](#table-of-contents)
## [2.5.1 - GET](#table-of-contents)

Retrieves information about a sample/file in JSON format. 

  + sample_get: Retrieves a sample by its SHA256 hash.
  + sample_get_md5: Retrieves a sample by its MD5 hash.

```python
import json
from maltiverse import Maltiverse
api = Maltiverse()

result = api.sample_get("b4e29d41ca04fccfa5d92be5bae506c556c6c880a4f5e9932f1e4a0766a2fd15")
print(json.dumps(result, indent=4, sort_keys=True))
```

```python
import json
from maltiverse import Maltiverse
api = Maltiverse()

result = api.sample_get_md5("e09f2eaebc86f54b48e4fb5101454535")
print(json.dumps(result, indent=4, sort_keys=True))
```

Output
```json
{
    "antivirus": [
        {
            "description": "AIT:Trojan.Nymeria.3070",
            "name": "MicroWorld-eScan"
        },
        {
            "description": "TrojanPWS.AutoIt.Zbot.S",
            "name": "CAT-QuickHeal"
        },
        {
            "description": "Dropper-AutoIt.i",
            "name": "McAfee"
        },
        {
            "description": "Unsafe",
            "name": "Cylance"
        },
        {
            "description": "malicious.ebc86f",
            "name": "Cybereason"
        },
        {
            "description": "heuristic",
            "name": "Invincea"
        },
        {
            "description": "ML.Attribute.HighConfidence",
            "name": "Symantec"
        },
        {
            "description": "a variant of Win32/TrojanDropper.Autoit.RF",
            "name": "ESET-NOD32"
        },
        {
            "description": "Malicious",
            "name": "APEX"
        },
        {
            "description": "AIT:Trojan.Nymeria.3070",
            "name": "BitDefender"
        },
        {
            "description": "malicious (high confidence)",
            "name": "Endgame"
        },
        {
            "description": "Dropper.DR/AutoIt.Gen8",
            "name": "F-Secure"
        },
        {
            "description": "BehavesLike.Win32.TrojanAitInject.wc",
            "name": "McAfee-GW-Edition"
        },
        {
            "description": "malicious.moderate.ml.score",
            "name": "Trapmine"
        },
        {
            "description": "Generic.mg.e09f2eaebc86f54b",
            "name": "FireEye"
        },
        {
            "description": "AIT:Trojan.Nymeria.3070 (B)",
            "name": "Emsisoft"
        },
        {
            "description": "DR/AutoIt.Gen8",
            "name": "Avira"
        },
        {
            "description": "Unsafe.AI_Score_71%",
            "name": "eGambit"
        },
        {
            "description": "Trojan:AutoIt/Prcablt.SD!MTB",
            "name": "Microsoft"
        },
        {
            "description": "AIT:Trojan.Nymeria.DBFE",
            "name": "Arcabit"
        },
        {
            "description": "AIT:Trojan.Nymeria.3070",
            "name": "GData"
        },
        {
            "description": "malware (ai score=88)",
            "name": "MAX"
        },
        {
            "description": "Trojan-Dropper.Win32.Autoit",
            "name": "Ikarus"
        },
        {
            "description": "Autoit/TrojanDropper.RF!tr",
            "name": "Fortinet"
        },
        {
            "description": "AI:Packer.08C9A85A16",
            "name": "BitDefenderTheta"
        },
        {
            "description": "HEUR/QVM10.1.0DC9.Malware.Gen",
            "name": "Qihoo-360"
        }
    ],
    "av_ratio": 36,
    "blacklist": [
        {
            "count": 1,
            "description": "AIT:Trojan.Nymeria",
            "first_seen": "2020-03-22 11:15:06",
            "last_seen": "2020-03-22 11:15:06",
            "source": "Hybrid-Analysis"
        }
    ],
    "classification": "malicious",
    "creation_time": "2020-03-22 11:15:06",
    "filename": [
        "steam-fix.exe"
    ],
    "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "md5": "e09f2eaebc86f54b48e4fb5101454535",
    "modification_time": "2020-03-22 11:15:06",
    "process_list": [
        {
            "name": "steam-fix.exe",
            "normalizedpath": "C:\\steam-fix.exe",
            "sha256": "b4e29d41ca04fccfa5d92be5bae506c556c6c880a4f5e9932f1e4a0766a2fd15",
            "uid": "00045091-00002896"
        },
        {
            "name": "svchost.exe",
            "normalizedpath": "%TEMP%\\svchost.exe",
            "sha256": "2cb251a4b4d0d0dde9af047873474e8fcf3d8100324150970da1cd0ef615fe22",
            "uid": "00045270-00000844"
        },
        {
            "name": "steam-idle.exe",
            "normalizedpath": "%TEMP%\\steam-idle.exe",
            "sha256": "026036ed63d90e292f90aa0fc7c51e985956776727fa736855ec8a7ea37d4d5f",
            "uid": "00045293-00003096"
        }
    ],
    "score": 10.0,
    "sha1": "9f3ed8c9378d957d68010d752f3142e710239a90",
    "sha256": "b4e29d41ca04fccfa5d92be5bae506c556c6c880a4f5e9932f1e4a0766a2fd15",
    "size": 3661312,
    "type": "sample"
}
```

