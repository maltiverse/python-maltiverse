import json
import requests
from urllib import quote_plus

class Maltiverse(object):

    def __init__(self, auth_token=None, endpoint='https://api.maltiverse.com'):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
        }
        if auth_token:
            self.session.headers.update({'Authorization': 'Token {0}'.format(auth_token)})

    def get(self, method, params=None):
        r = self.session.get(self.endpoint + method, params=params)
        r.raise_for_status()
        return r

    def post(self, method, params, headers=None):
        r = self.session.post(self.endpoint + method, data=json.dumps(params), headers=headers)
        r.raise_for_status()
        return r

    def ip_lookup(self, ip_addr):
        r = self.get('/ip/' + ip_addr)
        return json.loads(r.text)

    def domain_lookup(self, name):
        r = self.get('/domain/' + name)
        return json.loads(r.text)

    def url_lookup(self, location):
        r = self.get('/url/' + quote_plus(location))
        return json.loads(r.text)
