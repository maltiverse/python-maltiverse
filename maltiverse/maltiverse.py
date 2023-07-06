#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import hashlib
import jwt


class Maltiverse(object):
    def __init__(self, auth_token=None, endpoint="https://api.maltiverse.com"):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.sub = None
        self.team_name = None
        self.team_researcher = None
        self.admin = None

        self._default_headers = {"Accept": "application/json"}
        if self.auth_token:
            self._default_headers.update({"Authorization": f"Bearer {self.auth_token}"})

    def prepare_put_payload(self, params):
        """Auxiliar method to perform PUT requests to the platform"""
        if self.team_researcher and not self.admin:
            # Adding required information to push info being a researcher.
            if "blacklist" in params:
                # Is not allowed to specify dates
                if "creation_time" in params:
                    params.pop("creation_time", None)
                if "modification_time" in params:
                    params.pop("modification_time", None)

                if "domain" in params:
                    params.pop("domain", None)

                if "urlchecksum" in params:
                    params.pop("urlchecksum", None)

                if "tld" in params:
                    params.pop("tld", None)

                if "type" in params:
                    params.pop("type", None)

                for i, bl in enumerate(params["blacklist"]):
                    # Must set the ref
                    params["blacklist"][i]["ref"] = self.sub

                    # Must set the team name as the Blacklist source
                    params["blacklist"][i]["source"] = self.team_name

                    # Is not allowed to specify dates
                    if "first_seen" in params["blacklist"][i]:
                        params["blacklist"][i].pop("first_seen", None)
                    if "last_seen" in params["blacklist"][i]:
                        params["blacklist"][i].pop("last_seen", None)

        return json.dumps(params)

    def login(self, email, password):
        r_json = requests.post(
            self.endpoint + "/auth/login",
            data=json.dumps({"email": email, "password": password}),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        ).json()

        if "status" in r_json and r_json["status"] == "success":
            if r_json["auth_token"]:
                self.auth_token = str(r_json["auth_token"])
                decoded_payload = jwt.decode(
                    self.auth_token, options={"verify_signature": False}
                )
                self.sub = decoded_payload["sub"]
                self.team_name = decoded_payload["team_name"]
                self.team_researcher = decoded_payload["team_researcher"]
                self.admin = decoded_payload["admin"]
                return True

        raise Exception("Login Failed")

    def ip_get(self, ip_addr):
        """Requests an IP address"""
        return requests.get(
            f"{self.endpoint}/ip/{ip_addr}", headers=self._default_headers
        ).json()

    def ip_put(self, ip_dict):
        """Inserts a new Ip address observable.

        If it exists, the document is merged and stored.
        Requires authentication as admin
        """
        return requests.put(
            f"{self.endpoint}/ip/{ip_dict['ip_addr']}",
            data=self.prepare_put_payload(ip_dict),
            headers=dict(self._default_headers, **{"Content-Type": "application/json"}),
        ).json()

    def ip_delete(self, ip_addr):
        """Deletes Ip address observable. Requires authentication as admin"""
        return requests.delete(
            f"{self.endpoint}/ip/{ip_addr}", headers=self._default_headers
        ).json()

    def hostname_get(self, hostname):
        """Requests a hostname"""
        return requests.get(
            f"{self.endpoint}/hostname/{hostname}", headers=self._default_headers
        ).json()

    def hostname_put(self, hostname_dict):
        """Inserts a new hostname observable. If it exists, the document is merged and stored. Requires authentication as admin"""
        return requests.put(
            f"{self.endpoint}/hostname/{hostname_dict['hostname']}",
            data=self.prepare_put_payload(hostname_dict),
            headers=dict(self._default_headers, **{"Content-Type": "application/json"}),
        ).json()

    def hostname_delete(self, hostname):
        """Deletes hostname observable. Requires authentication as admin"""
        return requests.delete(
            f"{self.endpoint}/hostname/{hostname}", headers=self._default_headers
        ).json()

    def url_get(self, url):
        """Requests a url"""
        urlchecksum = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return requests.get(
            f"{self.endpoint}/url/{urlchecksum}", headers=self._default_headers
        ).json()

    def url_get_by_checksum(self, urlchecksum):
        """Requests a url by its sha256 checksum"""
        return requests.get(
            f"{self.endpoint}/url/{urlchecksum}", headers=self._default_headers
        ).json()

    def url_put(self, url_dict):
        """Inserts a new url observable. If it exists, the document is merged and stored. Requires authentication as admin"""
        urlchecksum = hashlib.sha256(url_dict["url"].encode("utf-8")).hexdigest()
        return requests.put(
            f"{self.endpoint}/url/{urlchecksum}",
            data=self.prepare_put_payload(url_dict),
            headers=dict(self._default_headers, **{"Content-Type": "application/json"}),
        ).json()

    def url_delete(self, url):
        """Deletes url observable. Requires authentication as admin"""
        urlchecksum = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return requests.delete(
            f"{self.endpoint}/url/{urlchecksum}",
            headers=self._default_headers,
        ).json()

    def sample_get(self, sample, algorithm="sha256"):
        """Requests a sample"""
        mapping = {
            "sha256": self.sample_get_by_sha256,
            "md5": self.sample_get_by_md5,
            "sha1": self.sample_get_by_sha1,
            "sha512": self.sample_get_by_sha512,
        }
        return mapping.get(algorithm, mapping.get("sha256"))()

    def sample_get_by_md5(self, md5):
        """Requests a sample by MD5"""
        return requests.get(
            f"{self.endpoint}/sample/md5/{md5}", headers=self._default_headers
        ).json()

    def sample_get_by_sha1(self, sha1):
        """Requests a sample by SHA1"""
        return requests.get(
            f"{self.endpoint}/sample/sha1/{sha1}", headers=self._default_headers
        ).json()

    def sample_get_by_sha256(self, sha256):
        """Requests a sample by SHA256"""
        return requests.get(
            f"{self.endpoint}/sample/{sha256}", headers=self._default_headers
        ).json()

    def sample_get_by_sha512(self, sha512):
        """Requests a sample by SHA512"""
        return requests.get(
            f"{self.endpoint}/sample/sha512/{sha512}", headers=self._default_headers
        ).json()

    def sample_put(self, sample_dict):
        """Inserts a new sample observable. If it exists, the document is merged and stored. Requires authentication as admin"""
        return requests.put(
            f"{self.endpoint}/sample/{sample_dict['sha256']}",
            data=self.prepare_put_payload(sample_dict),
            headers=dict(self._default_headers, **{"Content-Type": "application/json"}),
        ).json()

    def sample_delete(self, sha256):
        """Deletes sample observable. Requires authentication as admin"""
        return requests.delete(
            f"{self.endpoint}/sample/{sha256}", headers=self._default_headers
        ).json()

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
        """Performs a search into the Maltiverse platform."""
        params = dict()

        params["query"] = query

        if fr is not None:
            params["from"] = fr

        if size is not None:
            params["size"] = size

        if sort:
            params["sort"] = sort

        if range:
            params["range"] = range

        if range_field:
            params["range_field"] = range_field

        if format:
            params["format"] = format

        headers = {
            "Accept": "application/json",
        }
        if self.auth_token:
            headers["Authorization"] = "Bearer " + self.auth_token

        return requests.get(
            self.endpoint + "/search", params=params, headers=headers
        ).json()
