#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import unittest
import typing as t
from unittest.mock import MagicMock, patch
import requests
from maltiverse import Maltiverse
from maltiverse.maltiverse import T_AdminIndexScope
import time


class TestMaltiverse(unittest.TestCase):
    """Test for Maltiverse class"""

    def __init__(self, *args, **kwargs):
        super(TestMaltiverse, self).__init__(*args, **kwargs)
        self.email = "foo@mail.com"
        self.password = "fakepasswd"

    def test_login(self):
        """Test that performs an login"""
        m = Maltiverse()
        response_login = m.login(email=self.email, password=self.password)
        self.assertTrue(response_login, True)

    def test_admin_index_scope_literal_uses_showroom(self):
        """Ensure the admin index scope literal reflects the supported values."""
        self.assertEqual(
            t.get_args(T_AdminIndexScope), ("open", "restricted", "showroom")
        )

    def test_ip_get(self):
        """Test that performs an ip lookup"""
        m = Maltiverse()
        response_login = m.login(email=self.email, password=self.password)
        self.assertTrue(response_login, True)
        item = m.ip_get("1.1.1.1")
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("ip_addr" in item)

    def test_hostname_get(self):
        """Test that performs a hostname lookup"""
        m = Maltiverse()
        response_login = m.login(email=self.email, password=self.password)
        self.assertTrue(response_login, True)
        item = m.hostname_get("amazon.es")
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("hostname" in item)

    def test_search(self):
        """Test that performs search into the platform"""
        m = Maltiverse()
        print(m.login(email=self.email, password=self.password))
        item = m.search('country_code:"CN"', fr=0, size=2)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))

    def test_ip_put_delete(self):
        """Test that performs a IP put and a delete"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        ip_dict = {
            "blacklist": [{"description": "test", "source": "test"}],
            "classification": "whitelisted",
            "ip_addr": "60.60.60.60",
            "type": "ip",
        }
        item = m.ip_put(ip_dict)
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(
            item["message"] == "IP created" or item["message"] == "IP updated"
        )

        time.sleep(5)

        item = m.ip_delete(ip_dict["ip_addr"])
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(item["message"] == "IP deleted")

    def test_hostname_put_delete(self):
        """Test that performs a hostname put and a delete"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        hostname_dict = {
            "blacklist": [{"description": "test", "source": "test"}],
            "classification": "malicious",
            "domain": "testtesttesttesttesttesttest.com",
            "hostname": "testtesttesttesttesttesttest.com",
            "tld": "com",
            "type": "hostname",
        }
        item = m.hostname_put(hostname_dict)
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(
            item["message"] == "Hostname created"
            or item["message"] == "Hostname updated"
        )

        # Wait for five seconds to permit DB transaction happen
        time.sleep(5)

        item = m.hostname_delete(hostname_dict["hostname"])
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(item["message"] == "Hostname deleted")

    def test_url_get(self):
        """Test that performs an url lookup"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        item = m.url_get("http://m.tpsservices.runescape.com-no.ru/")
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("url" in item)

    def test_url_put_delete(self):
        """Test that performs a url put and a delete"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        url_dict = {
            "blacklist": [{"description": "test", "source": "test"}],
            "domain": "test.com",
            "hostname": "www.test.com",
            "type": "url",
            "url": "http://www.test.com/test.php",
        }
        item = m.url_put(url_dict)
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(
            item["message"] == "Url created" or item["message"] == "Url updated"
        )

        # Wait for two seconds to permit DB transaction happen
        time.sleep(5)

        item = m.url_delete(url_dict["url"])
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(item["message"] == "Url deleted")

    def test_sample_get(self):
        """Test that performs an sample lookup"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        item = m.sample_get(
            "3b9d4f379e59cfc5ed8217424c833fbd16e7bff322c2ea696870061bbd2c5273"
        )
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("sha256" in item)

    def test_sample_put_delete(self):
        """Test that performs a sample put and a delete"""
        m = Maltiverse()
        m.login(email=self.email, password=self.password)
        sample_dict = {
            "blacklist": [{"description": "test", "source": "test"}],
            "classification": "whitelisted",
            "filename": ["test"],
            "md5": "00000000000000000000000000000000",
            "sha1": "0000000000000000000000000000000000000000",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "sha512": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "type": "sample",
        }
        item = m.sample_put(sample_dict)
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(
            item["message"] == "Sample created" or item["message"] == "Sample updated"
        )

        # Wait for two seconds to permit DB transaction happen
        time.sleep(5)

        item = m.sample_delete(sample_dict["sha256"])
        print(item)
        self.assertTrue(isinstance(str(item), str))
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("status" in item)
        self.assertTrue(item["status"] == "success")
        self.assertTrue(item["message"] == "Sample deleted")


class TestMaltiverseIocHelpers(unittest.TestCase):
    """Unit tests for generic IOC helpers."""

    def test_ioc_put_uses_generic_endpoint(self):
        m = Maltiverse()
        ioc_dict = {"ip_addr": "1.1.1.1", "type": "ip"}
        with patch.object(m, "_request", return_value={"status": "success"}) as req:
            item = m.ioc_put(ioc_dict)
        req.assert_called_once()
        args, kwargs = req.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "https://api.maltiverse.com/ioc")
        self.assertEqual(kwargs["data"], '{"ip_addr": "1.1.1.1", "type": "ip"}')
        self.assertEqual(item["status"], "success")

    def test_ioc_delete_uses_generic_endpoint(self):
        m = Maltiverse()
        ioc_dict = {"hostname": "example.com", "type": "hostname"}
        with patch.object(m, "_request", return_value={"status": "success"}) as req:
            item = m.ioc_delete(ioc_dict)
        req.assert_called_once()
        args, kwargs = req.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertEqual(args[1], "https://api.maltiverse.com/ioc")
        self.assertEqual(
            kwargs["data"], '{"hostname": "example.com", "type": "hostname"}'
        )
        self.assertEqual(item["status"], "success")


class TestMaltiverseBulk(unittest.TestCase):
    """Unit tests for the /bulk upsert helpers."""

    def _mock_response(self, status_code=200, json_body=None, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.ok = 200 <= status_code < 400
        resp.text = text
        if json_body is None:
            resp.json.side_effect = ValueError("no body")
        else:
            resp.json.return_value = json_body
        return resp

    def test_bulk_upsert_posts_list_payload(self):
        m = Maltiverse()
        indicators = [
            {"ip_addr": "1.1.1.1", "type": "ip"},
            {"hostname": "example.com", "type": "hostname"},
        ]
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(json_body={"status": "success"}),
        ) as post:
            result = m.bulk_upsert(indicators)
        post.assert_called_once()
        _, kwargs = post.call_args
        self.assertEqual(kwargs["params"], {"enrich": "true"})
        self.assertEqual(json.loads(kwargs["data"]), indicators)
        self.assertEqual(post.call_args[0][0], "https://api.maltiverse.com/bulk")
        self.assertEqual(result, {"status": "success"})

    def test_bulk_upsert_accepts_indicators_dict(self):
        m = Maltiverse()
        body = {"indicators": [{"ip_addr": "1.1.1.1", "type": "ip"}]}
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(json_body={"status": "success"}),
        ) as post:
            m.bulk_upsert(body)
        self.assertEqual(json.loads(post.call_args.kwargs["data"]), body)

    def test_bulk_upsert_rejects_dict_without_indicators(self):
        m = Maltiverse()
        with self.assertRaises(ValueError):
            m.bulk_upsert({"foo": "bar"})

    def test_bulk_upsert_enrich_false(self):
        m = Maltiverse()
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(json_body={"status": "success"}),
        ) as post:
            m.bulk_upsert([{"ip_addr": "1.1.1.1", "type": "ip"}], enrich=False)
        self.assertEqual(post.call_args.kwargs["params"], {"enrich": "false"})

    def test_bulk_upsert_buffered_omits_enrich(self):
        m = Maltiverse()
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(
                status_code=202, json_body={"task": "abc"}
            ),
        ) as post:
            m.bulk_upsert(
                [{"ip_addr": "1.1.1.1", "type": "ip"}], buffered=True, enrich=True
            )
        self.assertEqual(post.call_args.kwargs["params"], {"buffered": "true"})

    def test_bulk_upsert_buffered_sets_query_params(self):
        m = Maltiverse()
        indicators = [{"ip_addr": "1.1.1.1", "type": "ip"}]
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(
                status_code=202, json_body={"task": "abc-123"}
            ),
        ) as post:
            result = m.bulk_upsert(
                indicators, buffered=True, index_scope="restricted"
            )
        _, kwargs = post.call_args
        self.assertEqual(
            kwargs["params"], {"buffered": "true", "index_scope": "restricted"}
        )
        self.assertEqual(result, {"task": "abc-123"})

    def test_bulk_upsert_buffered_omits_scope_when_unset(self):
        m = Maltiverse()
        with patch(
            "maltiverse.maltiverse.requests.post",
            return_value=self._mock_response(
                status_code=202, json_body={"task": "abc"}
            ),
        ) as post:
            m.bulk_upsert(
                [{"ip_addr": "1.1.1.1", "type": "ip"}], buffered=True
            )
        self.assertEqual(post.call_args.kwargs["params"], {"buffered": "true"})

    def test_bulk_upsert_raises_http_error_surfacing_server_message(self):
        m = Maltiverse()
        resp = self._mock_response(
            status_code=400,
            json_body={"status": "fail", "message": "enrich not allowed"},
        )
        with patch("maltiverse.maltiverse.requests.post", return_value=resp):
            with self.assertRaises(requests.HTTPError) as ctx:
                m.bulk_upsert(
                    [{"ip_addr": "1.1.1.1", "type": "ip"}], buffered=True
                )
        self.assertIn("enrich not allowed", str(ctx.exception))
        self.assertIn("fail", str(ctx.exception))
        self.assertIs(ctx.exception.response, resp)

    def test_bulk_upsert_raises_http_error_without_json_body(self):
        m = Maltiverse()
        resp = self._mock_response(status_code=500, text="boom")
        resp.raise_for_status.side_effect = requests.HTTPError(
            "500 Server Error", response=resp
        )
        with patch("maltiverse.maltiverse.requests.post", return_value=resp):
            with self.assertRaises(requests.HTTPError):
                m.bulk_upsert([{"ip_addr": "1.1.1.1", "type": "ip"}])


if __name__ == "__main__":
    unittest.main()
