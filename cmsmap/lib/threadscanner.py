#! /usr/bin/env python3
import urllib, http.client, threading, time, socket

# Import Object
from .initialize import initializer
from .report import report
from .requester import requester


class ThreadScanner(threading.Thread):
    # Implements Multi-Threads
    # self.url = http://mysite.com
    # pluginPath = /wp-content
    # pluginPathEnd = /
    # pluginFound = wptest
    def __init__(self, url, pluginPath, pluginPathEnd, pluginsFound, notExistingCode, notValidLen, q):
        threading.Thread.__init__(self)
        self.url = url
        self.q = q
        self.pluginPath = pluginPath
        self.pluginsFound = pluginsFound
        self.pluginPathEnd = pluginPathEnd
        self.notExistingCode = notExistingCode
        self.notValidLen = notValidLen

    def run(self):
        while True:
            # Get plugin from plugin queue
            plugin = self.q.get()
            requester.request(self.url + self.pluginPath + plugin + self.pluginPathEnd, data=None)
            if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
                self.pluginsFound.append(plugin)
            elif requester.status_code != self.notExistingCode and len(requester.htmltext) not in self.notValidLen:
                self.pluginsFound.append(plugin)
            self.q.task_done()

# Used by BruteForcer. Then can be deleted
class MyResponse(http.client.HTTPResponse):
    # Reads responds for no redirection requests
    def read(self, amt=None):
        self.length = None
        return http.client.HTTPResponse.read(self, amt)

# Used by BruteForcer. Then can be deleted
class MyHandler(urllib.request.HTTPHandler):
    def do_open(self, http_class, req):
        h = http.client.HTTPConnection
        h.response_class = MyResponse
        return urllib.request.HTTPHandler.do_open(self, h, req)
