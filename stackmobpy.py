"""
The MIT License

Copyright (c) 2013 Pavlo Aksonov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

"""
 First version supports insert/select/update/delete/login operations with OAuth2.0 authorization. Login is done
 automatically during insert/update/delete.

 If access_token is expired, new access token will be automatically retrieved
"""

import json
import httplib
from time import time
from random import randrange
from hashlib import sha1
from hmac import new as hmac
import unittest

VERSION = '0.1'


class StackMobClient(object):
    public_key = None
    base_url = 'api.stackmob.com'
    username = None
    password = None
    version = "0"
    _access_token = None
    _expire = None
    _mac_key = None

    def __init__(self, public_key, username=None, password=None, version='0'):
        self.public_key = public_key
        assert self.public_key, 'Please define your StackMob public key!'
        self.username = username
        self.password = password
        self.version = version

    def _request(self, method, path, data=None, contentType="application/json", authHeader=None):
        # try to set authorization header
        if not authHeader:
            authHeader = self._auth_header(method, path)

        # make connection
        connection = httplib.HTTPConnection(self.base_url)
        connection.connect()
        connection.request(method, path, data, {
            "Content-Type": contentType,
            "X-StackMob-User-Agent": "Python StackMob client version %s" % VERSION,
            "Accept": "application/vnd.stackmob+json; version=%s" % self.version,
            "Authorization": authHeader,
            "X-StackMob-API-Key": self.public_key})

        resp = connection.getresponse()
        return resp

    def _login(self):
        resp = self._request('POST', '/user/accessToken', "username=%s&password=%s&token_type=mac" % (self.username,
                             self.password), contentType="application/x-www-form-urlencoded", authHeader='login')
        r = json.loads(resp.read())
        if r.get('access_token'):
            self._access_token = r['access_token']
            self._mac_key = r['mac_key']
            self._expire = int(r['expires_in'])
        else:
            raise Exception(r)

    def _create_base_string(self, ts, nonce, method, uri, host, port):
        return u"%s\n%s\n%s\n%s\n%s\n%s\n\n" %(ts, nonce, method, uri, host, port)

    def _generate_MAC(self, method, id, key, hostWithPort, url):
        splitHost = hostWithPort.split(':')
        hostNoPort = hostWithPort
        if len(splitHost) > 1:
            hostNoPort = splitHost[0]

        port = 80

        if len(splitHost) > 1:
            port = splitHost[1]

        ts = '%d' % int(round(time()))
        nonce = "n%d" % int(round(randrange(0, 10000)))

        base = self._create_base_string(ts, nonce, method, url, hostNoPort, port)

        res = hmac(key.encode(), base, sha1)
        mac = res.digest().encode("base64").strip()

        return 'MAC id="' + id + '",ts="' + ts + '",nonce="' + nonce + '",mac="' + mac + '"'

    def _auth_header(self, method, path):
        if not self.username:
            return None
        if (not self._access_token) or (self._expire and self._expire < time()):
            self._login()

        res = self._generate_MAC(method, self._access_token, self._mac_key, self.base_url, path)
        return res

    def select(self, entity, entity_id=''):
        path = '/%s' % entity
        if entity_id:
            path = '%s/%s' % (path, entity_id)

        resp = self._request('GET', path)
        r = resp.read()
        if (resp.status == 200) and r:
            rec = json.loads(r)
            return rec
        else:
            # return None for 404 error code, exception otherwise
            if resp.status != 404:
                raise Exception('Error code %s, response %s' % (resp.status, r))
            else:
                return None

    def insert(self, entity, data):
        assert entity, 'Entity should not be empty'
        assert data, 'Data should not be empty'
        resp = self._request('POST', '/%s' % entity, json.dumps(data))
        r = resp.read()
        if resp.status != 201:
            if resp.status == 401:
                # Trying to login again
                self._login()
                self.insert(entity, data)
                return

            raise Exception('Error code %s, response %s' % (resp.status, r))
        else:
            return r

    def update(self, entity, entity_id, data):
        assert entity, 'Entity should not be empty'
        assert data, 'Data should not be empty'
        assert entity_id, 'entity_id should not be empty'

        resp = self._request('PUT', '/%s/%s' % (entity, entity_id), json.dumps(data))
        r = resp.read()
        if resp.status != 200:
            if resp.status == 401:
                # Trying to login again
                self._login()
                self.update(entity, entity_id, data)
                return
            raise Exception('Error code %s, response %s' % (resp.status, r))
        else:
            return r

    def delete(self, entity, entity_id):
        assert entity, 'Entity should not be empty'
        assert entity_id, 'entity_id should not be empty'

        resp = self._request('DELETE', '/%s/%s' % (entity, entity_id))
        r = resp.read()
        if resp.status != 200:
            raise Exception('Error code %s, response %s' % (resp.status, r))
        else:
            return r


"""
Unit tests for StackMob client. Testing environment app contains 'admin' user with 'admin' role who could select/insert/
update and delete records from 'test' table.
"""

TEST_API_KEY = "3c2d9794-ab29-49c9-80ba-f31664af0380"
TEST_USER = "admin"
TEST_PASSWORD = "adminpassword"


class StackMobClientTestCase(unittest.TestCase):
    client = None

    def setUp(self):
        self.client = StackMobClient(TEST_API_KEY, username=TEST_USER, password=TEST_PASSWORD)
        if self.client.select('test', '123'):
            self.client.delete('test', '123')

    def testInsert(self):
        # insert record
        self.client.insert('test', {'test_id':"123", 'test_name':'TEST_NAME'})

        # read record
        rec = self.client.select('test', '123')
        self.assertEqual('123', rec['test_id'])
        self.assertEqual('TEST_NAME', rec['test_name'])

    def testUpdate(self):
        # insert record
        self.client.insert('test', {'test_id':"123", 'test_name':'TEST_NAME'})

        # read record
        rec = self.client.select('test', '123')
        self.assertEqual('123', rec['test_id'])
        self.assertEqual('TEST_NAME', rec['test_name'])

        # update record
        self.client.update('test', '123', {'test_name': "UPDATED_NAME"})
        # read record
        rec = self.client.select('test', '123')
        self.assertEqual('123', rec['test_id'])
        self.assertEqual('UPDATED_NAME', rec['test_name'])



