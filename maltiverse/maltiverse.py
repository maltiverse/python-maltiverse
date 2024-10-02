#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import hashlib
import jwt


class Maltiverse:
    def __init__(self, auth_token=None, endpoint="https://api.maltiverse.com"):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.sub = None
        self.team_name = None
        self.team_researcher = None
        self.admin = None
        self._default_headers = self._create_headers()

    def _create_headers(self):
        """Create default headers with or without authentication token."""
        headers = {"Accept": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _update_headers(self, additional_headers):
        """Update headers with additional headers provided."""
        return {**self._default_headers, **additional_headers}

    def prepare_put_payload(self, params):
        """Prepare the payload for PUT requests, removing fields based on user permissions."""
        if self.team_researcher and not self.admin and "blacklist" in params:
            self._sanitize_blacklist(params)
        return json.dumps(params)

    def _sanitize_blacklist(self, params):
        """Clean restricted fields and add required information to the blacklist."""
        restricted_fields = [
            "creation_time",
            "modification_time",
            "domain",
            "urlchecksum",
            "tld",
            "type",
        ]
        for field in restricted_fields:
            params.pop(field, None)

        for bl_item in params.get("blacklist", []):
            bl_item["ref"] = self.sub
            bl_item["source"] = self.team_name
            bl_item.pop("first_seen", None)
            bl_item.pop("last_seen", None)

    def login(self, email, password):
        """Logs in and stores the authentication token and user details."""
        response = requests.post(
            f"{self.endpoint}/auth/login",
            data=json.dumps({"email": email, "password": password}),
            headers=self._update_headers({"Content-Type": "application/json"}),
        ).json()

        if response.get("status") == "success" and "auth_token" in response:
            self.auth_token = response["auth_token"]
            self._default_headers = self._create_headers()
            self._decode_token()
            return True
        raise Exception("Login Failed")

    def _decode_token(self):
        """Decodes the JWT token and stores user details."""
        decoded_payload = jwt.decode(
            self.auth_token, options={"verify_signature": False}
        )
        self.sub = decoded_payload.get("sub")
        self.team_name = decoded_payload.get("team_name")
        self.team_researcher = decoded_payload.get("team_researcher")
        self.admin = decoded_payload.get("admin")

    def _request(self, method, url, headers=None, **kwargs):
        """Make an HTTP request with the specified method."""
        headers = headers or self._default_headers
        return requests.request(method, url, headers=headers, **kwargs).json()

    def ip_get(self, ip_addr):
        """Fetch information for a given IP address."""
        return self._request("GET", f"{self.endpoint}/ip/{ip_addr}")

    def ip_put(self, ip_dict):
        """Update or insert an IP address observable."""
        return self._request(
            "PUT",
            f"{self.endpoint}/ip/{ip_dict['ip_addr']}",
            headers=self._update_headers({"Content-Type": "application/json"}),
            data=self.prepare_put_payload(ip_dict),
        )

    def ip_delete(self, ip_addr):
        """Delete an IP address observable."""
        return self._request("DELETE", f"{self.endpoint}/ip/{ip_addr}")

    def hostname_get(self, hostname):
        """Fetch information for a given hostname."""
        return self._request("GET", f"{self.endpoint}/hostname/{hostname}")

    def hostname_put(self, hostname_dict):
        """Update or insert a hostname observable."""
        return self._request(
            "PUT",
            f"{self.endpoint}/hostname/{hostname_dict['hostname']}",
            headers=self._update_headers({"Content-Type": "application/json"}),
            data=self.prepare_put_payload(hostname_dict),
        )

    def hostname_delete(self, hostname):
        """Delete a hostname observable."""
        return self._request("DELETE", f"{self.endpoint}/hostname/{hostname}")

    def url_get(self, url):
        """Fetch information for a given URL."""
        urlchecksum = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self._request("GET", f"{self.endpoint}/url/{urlchecksum}")

    def url_get_by_checksum(self, urlchecksum):
        """Fetch a URL by its SHA256 checksum."""
        return self._request("GET", f"{self.endpoint}/url/{urlchecksum}")

    def url_put(self, url_dict):
        """Update or insert a URL observable."""
        urlchecksum = hashlib.sha256(url_dict["url"].encode("utf-8")).hexdigest()
        return self._request(
            "PUT",
            f"{self.endpoint}/url/{urlchecksum}",
            headers=self._update_headers({"Content-Type": "application/json"}),
            data=self.prepare_put_payload(url_dict),
        )

    def url_delete(self, url):
        """Delete a URL observable."""
        urlchecksum = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self._request("DELETE", f"{self.endpoint}/url/{urlchecksum}")

    def sample_get(self, sample, algorithm="sha256"):
        """Fetch a sample using a hash algorithm (MD5, SHA1, SHA256, SHA512)."""
        hash_methods = {
            "md5": self.sample_get_by_md5,
            "sha1": self.sample_get_by_sha1,
            "sha256": self.sample_get_by_sha256,
            "sha512": self.sample_get_by_sha512,
        }
        return hash_methods.get(algorithm, self.sample_get_by_sha256)(sample)

    def sample_get_by_md5(self, md5):
        return self._request("GET", f"{self.endpoint}/sample/md5/{md5}")

    def sample_get_by_sha1(self, sha1):
        return self._request("GET", f"{self.endpoint}/sample/sha1/{sha1}")

    def sample_get_by_sha256(self, sha256):
        return self._request("GET", f"{self.endpoint}/sample/{sha256}")

    def sample_get_by_sha512(self, sha512):
        return self._request("GET", f"{self.endpoint}/sample/sha512/{sha512}")

    def sample_put(self, sample_dict):
        """Update or insert a sample observable."""
        return self._request(
            "PUT",
            f"{self.endpoint}/sample/{sample_dict['sha256']}",
            headers=self._update_headers({"Content-Type": "application/json"}),
            data=self.prepare_put_payload(sample_dict),
        )

    def sample_delete(self, sha256):
        """Delete a sample observable."""
        return self._request("DELETE", f"{self.endpoint}/sample/{sha256}")

    def search(
        self,
        query,
        fr=None,
        size=None,
        sort=None,
        range=None,
        range_field=None,
        format=None,
    ):
        """Perform a search on the Maltiverse platform."""
        params = {
            "query": query,
            "from": fr,
            "size": size,
            "sort": sort,
            "range": range,
            "range_field": range_field,
            "format": format,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._request("GET", f"{self.endpoint}/search", params=params)
