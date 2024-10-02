![Maltiverse Logo](https://maltiverse.com/assets/images/logo/logo_letters_black.png)

# python-maltiverse

A Python library for interacting with the [Maltiverse](https://www.maltiverse.com/) API.

This package simplifies requests to the Maltiverse IoC (Indicator of Compromise) search engine API. The full API definition can be found here: [Maltiverse API](https://app.swaggerhub.com/apis-docs/maltiverse/api/1.0.0-oas3).

---

## Table of Contents
1. [Installation](#1-installation)
2. [Usage](#2-usage)
   - [Authentication](#21-authentication)
   - [IPv4 Information](#22-ipv4)
   - [Hostname Information](#23-hostname)
   - [URL Information](#24-url)
   - [Sample Information](#25-sample)
   - [Feed Information](#26-feed)

---

## 1. Installation

To install the package, use `pip`:

```bash
pip install maltiverse
```

---

## 2. Usage

### 2.1 Authentication

Maltiverse uses OAuth 2.0 Bearer tokens with JWT (JSON Web Tokens) for authentication. JWT ensures secure transmission of information between parties. You can authenticate using either your account credentials or an API key, depending on your needs.

#### 2.1.1 Authenticating with Credentials
You can log in to your Maltiverse account by providing your email and password:

```python
from maltiverse import Maltiverse

api = Maltiverse()
api.login(email="your_email", password="your_password")
```

#### 2.1.2 Authenticating with API Key
You can generate a permanent API key in your profile page once registered. Use this API key for scenarios where it's required:

```python
from maltiverse import Maltiverse

api = Maltiverse(auth_token="your_api_key")
```

Once authenticated, API requests will automatically include the necessary JWT for access.

---

### 2.2 IPv4 Information

#### 2.2.1 Retrieve IPv4 Details

To get detailed information about an IPv4 address, use the `ip_get()` method. The response includes the IP's reputation, associated blacklist reports, and more.

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.ip_get("110.189.222.98")
print(json.dumps(result, indent=4, sort_keys=True))
```

Sample output:

```json
{
    "ip_addr": "110.189.222.98",
    "asn_country_code": "CN",
    "blacklist": [
        {
            "source": "Blocklist.de",
            "description": "Mail Spammer",
            "first_seen": "2017-11-30",
            "last_seen": "2017-11-30"
        }
    ],
    "classification": "malicious",
    "country_code": "CN",
    "location": {
        "lat": 30.6667,
        "lon": 104.0667
    },
    "registrant_name": "CHINANET Sichuan"
}
```

---

### 2.3 Hostname Information

#### 2.3.1 Retrieve Hostname Details

Get detailed information about a specific hostname, including blacklist reports, classification, and resolved IPs:

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.hostname_get("59022.flatblastard.com")
print(json.dumps(result, indent=4, sort_keys=True))
```

Sample output:

```json
{
    "hostname": "59022.flatblastard.com",
    "classification": "malicious",
    "resolved_ip": [
        {
            "ip_addr": "91.207.4.51",
            "timestamp": "2020-03-22"
        }
    ],
    "tag": ["ponmocup", "malware"]
}
```

---

### 2.4 URL Information

#### 2.4.1 Retrieve URL Details

Retrieve information about a specific URL, including blacklist reports, phishing activity, and classification:

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.url_get("https://alleom.com/weqmo")
print(json.dumps(result, indent=4, sort_keys=True))
```

Sample output:

```json
{
    "url": "https://alleom.com/weqmo",
    "classification": "malicious",
    "blacklist": [
        {
            "source": "Phishtank",
            "description": "Phishing Other",
            "first_seen": "2020-03-22"
        }
    ],
    "tag": ["phishing"]
}
```

---

### 2.5 Sample Information

#### 2.5.1 Retrieve Sample Details

You can retrieve information about a malware sample by providing its SHA256 or MD5 hash.

To get details with a SHA256 hash:

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.sample_get("b4e29d41ca04fccfa5d92be5bae506c556c6c880a4f5e9932f1e4a0766a2fd15")
print(json.dumps(result, indent=4, sort_keys=True))
```

To get details with an MD5 hash:

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.sample_get_md5("e09f2eaebc86f54b48e4fb5101454535")
print(json.dumps(result, indent=4, sort_keys=True))
```

Sample output:

```json
{
    "md5": "e09f2eaebc86f54b48e4fb5101454535",
    "classification": "malicious",
    "av_ratio": 36,
    "antivirus": [
        {
            "name": "MicroWorld-eScan",
            "description": "AIT:Trojan.Nymeria.3070"
        }
    ]
}
```

---

### 2.6 Feed Information

#### 2.6.1 Retrieve Feed Data

You can retrieve feed metadata or download a specific feed from Maltiverse.

To download a specific feed:

```python
import json
from maltiverse import Maltiverse

api = Maltiverse()
result = api.feed_download("VdhZV34B4jHUXfKt_gDi")  # Command & Control feed
print(json.dumps(result, indent=4))
```

The result contains details of the selected feed.
