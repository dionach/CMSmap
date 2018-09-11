#! /usr/bin/env python3
import urllib, ssl, http.cookiejar

# Import Objects 
from .initialize import initializer

class Requester:
    def __init__(self):
        self.htmltext = None
        self.status_code = None
        self.headers = initializer.headers
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.cookieJar = http.cookiejar.CookieJar()
        self.cookieHandler = urllib.request.HTTPCookieProcessor(self.cookieJar)

    def request(self, url, data):
        self.url = url
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data : data = data.encode('utf-8')
        self.req = urllib.request.Request(url=url, data=data, headers=self.headers)
        urllib.request.install_opener(urllib.request.build_opener())
        try:
            # Returns 200
            if initializer.nosslcheck :
                self.response = urllib.request.urlopen(self.req, context=self.ctx)
            else:
                self.response = urllib.request.urlopen(self.req)
            # it will ignore any bad character without replacing it
            self.htmltext = self.response.read().decode('utf-8', 'ignore')
            self.status_code = 200
        except urllib.request.HTTPError as e:
            # Does not return  200
            self.response = e
            self.htmltext = e.read().decode('utf-8', 'ignore')
            self.status_code = e.code

    def noredirect(self, url, data):
        self.url = url
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data : data = data.encode('utf-8')
        self.req = urllib.request.Request(url=url, data=data, headers=self.headers)
        urllib.request.install_opener(urllib.request.build_opener(NoRedirects()))
        try:
            # Returns 200
            if initializer.nosslcheck :
                self.response = urllib.request.urlopen(self.req, context=self.ctx)
            else:
                self.response = urllib.request.urlopen(self.req)
            self.htmltext = self.response.read().decode('utf-8', 'ignore')
            self.status_code = 200
        except urllib.request.HTTPError as e:
            # Does not return  200
            self.response = e
            self.htmltext = e.read().decode('utf-8', 'ignore')
            self.status_code = e.code

    def requestcookie(self, url, data):
        self.url = url
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data : data = data.encode('utf-8')
        self.req = urllib.request.Request(url=url, data=data, headers=self.headers)
        urllib.request.install_opener(urllib.request.build_opener(self.cookieHandler))
        try:
            # Returns 200
            if initializer.nosslcheck :
                self.response = urllib.request.urlopen(self.req, context=self.ctx)
            else:
                self.response = urllib.request.urlopen(self.req)
            # it will ignore any bad character without replacing it
            self.htmltext = self.response.read().decode('utf-8', 'ignore')
            self.status_code = 200
        except urllib.request.HTTPError as e:
            # Does not return  200
            self.response = e
            self.htmltext = e.read().decode('utf-8', 'ignore')
            self.status_code = e.code

class NoRedirects(urllib.request.HTTPRedirectHandler):
    # Redirect handler that simply raises a Redirect() for all http_error_30*() methods
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        RedirError = urllib.request.HTTPError(req.get_full_url(), code, msg, headers, fp)
        RedirError.status = code
        raise RedirError

requester = Requester()
