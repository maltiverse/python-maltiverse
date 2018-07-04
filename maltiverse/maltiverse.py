#!/usr/bin/python
# -*- coding: utf-8 -*-


import json
import requests
import hashlib
from urllib import quote_plus

import base64



class Maltiverse(object):

    def __init__(self, auth_token=None, endpoint='https://api.maltiverse.com'):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.sub = None
        self.team_name = None
        self.team_researcher = None
        self.admin = None
        self.session = requests.Session()
        self.session.headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
        }
        if auth_token:
            self.session.headers.update({'Authorization': 'Bearer ' + self.auth_token})

    def get(self, method, params=None):
        r = self.session.get(self.endpoint + method, params=params)
        #r.raise_for_status()
        return r

    def put(self, method, params):
        if self.team_researcher and not self.admin:
            if 'blacklist' in params:
                new_blacklist = []
                for bl in params['blacklist']:
                    bl['ref'] = self.sub
                    bl['source'] = self.team_name
                    new_blacklist.push(bl)
                params['blacklist'] = new_blacklist
        r = self.session.put(self.endpoint + method, data=json.dumps(params))
        print self.session.headers

        return r

    def post(self, method, params):
        r = self.session.post(self.endpoint + method, data=json.dumps(params))
        #r.raise_for_status()
        return r

    def delete(self, method):
        r = self.session.delete(self.endpoint + method)
        #r.raise_for_status()
        return r

    def login(self, email, password):
        r = self.post('/auth/login',{'email': email, 'password': password})
        r_json = json.loads(r.text)

        if 'status' in r_json and r_json['status'] == 'success':
            if r_json['auth_token']:
                self.auth_token = r_json['auth_token']
                decoded_payload = json.loads(base64.b64decode(r_json['auth_token'].split('.')[1]))
                self.sub = decoded_payload['sub']
                self.team_name = decoded_payload['team_name']
                self.team_researcher = decoded_payload['team_researcher']
                self.admin = decoded_payload['admin']
                self.session.headers.update({'Authorization': 'Bearer ' + self.auth_token})
                return True
        return False

    def ip_get(self, ip_addr):
        ''' Requests an IP address '''
        r = self.get('/ip/' + ip_addr)
        return json.loads(r.text)

    def ip_put(self, ip_dict):
        ''' Inserts a new Ip address observable. If it exists, the document is merged and stored. Requires authentication as admin'''
        r = self.put('/ip/' + ip_dict['ip_addr'], params=ip_dict)
        return json.loads(r.text)

    def ip_delete(self, ip_addr):
        ''' Deletes Ip address observable. Requires authentication as admin'''
        r = self.delete('/ip/' + ip_addr)
        return json.loads(r.text)

    def hostname_get(self, hostname):
        ''' Requests a hostname '''
        r = self.get('/hostname/' + hostname)
        return json.loads(r.text)

    def hostname_put(self, hostname_dict):
        ''' Inserts a new hostname observable. If it exists, the document is merged and stored. Requires authentication as admin'''
        r = self.put('/hostname/' + hostname_dict['hostname'], params=hostname_dict)
        return json.loads(r.text)

    def hostname_delete(self, hostname):
        ''' Deletes hostname observable. Requires authentication as admin'''
        r = self.delete('/hostname/' + hostname)
        return json.loads(r.text)

    def url_get(self, url):
        ''' Requests a url '''
        urlchecksum = hashlib.sha256(url).hexdigest()
        r = self.get('/url/' + urlchecksum)
        return json.loads(r.text)

    def url_put(self, url_dict):
        ''' Inserts a new url observable. If it exists, the document is merged and stored. Requires authentication as admin'''
        urlchecksum = hashlib.sha256(url_dict['url']).hexdigest()
        r = self.put('/url/' + urlchecksum, params=url_dict)
        return json.loads(r.text)

    def url_delete(self, url):
        ''' Deletes url observable. Requires authentication as admin'''
        urlchecksum = hashlib.sha256(url).hexdigest()
        r = self.delete('/url/' + urlchecksum)
        return json.loads(r.text)

    def sample_get(self, sha256):
        ''' Requests a sample '''
        r = self.get('/sample/' + sha256)
        return json.loads(r.text)

    def sample_put(self, sample_dict):
        ''' Inserts a new sample observable. If it exists, the document is merged and stored. Requires authentication as admin'''
        r = self.put('/sample/' + sample_dict['sha256'], params=sample_dict)
        return json.loads(r.text)

    def sample_delete(self, sha256):
        ''' Deletes sample observable. Requires authentication as admin'''
        r = self.delete('/sample/' + sha256)
        return json.loads(r.text)

    def sample_get_by_md5(self, md5):
        ''' Requests a sample by MD5 '''
        r = self.get('/search?query=md5:"' + md5 + '"')
        return json.loads(r.text)