#! /usr/bin/env python3
import sys, re, time, queue

#Import Object
from urllib.parse import urlparse
from .initialize import initializer
from .report import report
from .requester import requester

#Import Class
from .threadscanner import ThreadScanner


# Perform web application generic checks
class GenericChecks:

    def __init__(self):
        self.url = None
        self.headers = initializer.headers
        self.notExistingCode = 404
        self.thread_num = 5
        self.commExt = ['.txt', '.php', '/', '.html']
        self.notValidLen = []
        self.commFiles = [line.strip() for line in open(initializer.commFiles)]

    # Validate the URL provided
    def CheckURL(self):
        pUrl = urlparse(self.url)
        initializer.netloc = pUrl.netloc.lower()
        initializer.scheme = pUrl.scheme.lower()
        path = pUrl.path.lower()
        if not initializer.scheme:
            self.url = "http://" + self.url
            report.status("No HTTP/HTTPS provided. Assuming HTTP...")
        if path.endswith("asp" or "aspx"):
            report.error("You are not scanning a PHP website")
            sys.exit(1)
        if path.endswith("txt" or "php"):
            self.url = re.findall(
                re.compile('(.+?)/[A-Za-z0-9]+\.txt|php'), self.url)[0]

    # Check if directory is listing
    def DirectoryListing(self, relPath):
        self.relPath = relPath
        msg = "Checking directory listing: " + self.relPath
        report.verbose(msg)
        requester.request(self.url + self.relPath, data=None)
        dirList = re.search("<title>Index of", requester.htmltext, re.IGNORECASE)
        if dirList: 
            msg = self.url + self.relPath
            report.low(msg)
        
    # Check if website is over HTTPS
    def HTTPSCheck(self):
        msg = "Checking if the website is in HTTPS ..."
        report.verbose(msg)
        pUrl = urlparse(self.url)
        scheme = pUrl.scheme.lower()
        if scheme == 'http':
            # check HTTPS redirection
            requester.noredirect(self.url, data=None)
            if requester.status_code == 200 :
                msg = "Website Not in HTTPS: " + self.url
                report.medium(msg)
            else:
                redirected = re.search("https", str(requester.htmltext), re.IGNORECASE)
                if requester.status_code != 302 and not redirected:
                    msg = "Website Not in HTTPS: " + self.url
                    report.medium(msg)

    # Check Security Headers
    def HeadersCheck(self):
        requester.request(self.url, data=None)
        msg = "Checking headers ..."
        report.verbose(msg)
        if requester.response.info().get('Server'):
            msg = "Server: " + requester.response.info().get('Server')
            report.info(msg)
        if requester.response.info().get('X-Powered-By'):
            msg = "X-Powered-By: " + requester.response.info().get('X-Powered-By')
            report.info(msg)
        if requester.response.info().get('X-Generator'):
            msg = "X-Generator: " + requester.response.info().get('X-Generator')
            report.low(msg)
        if requester.response.info().get('x-xss-protection') == '0':
            msg = "X-XSS-Protection Disabled"
            report.high(msg)
        if not requester.response.info().get('x-frame-options') or (
                requester.response.info().get('x-frame-options').lower() != 'sameorigin' or 'deny'):
            msg = "X-Frame-Options: Not Enforced"
            report.low(msg)
        if not requester.response.info().get('strict-transport-security'):
            msg = "Strict-Transport-Security: Not Enforced"
            report.info(msg)
        if not requester.response.info().get('x-content-security-policy'):
            msg = "X-Content-Security-Policy: Not Enforced"
            report.info(msg)
        if not requester.response.info().get('x-content-type-options'):
            msg = "X-Content-Type-Options: Not Enforced"
            report.info(msg)
        
    # Check if AutoComplete is set to Off on login pages
    def AutocompleteOff(self, relPath):
        msg = "Checking Autocomplete Off on the login page ..."
        report.verbose(msg)
        self.relPath = relPath
        requester.request(self.url + self.relPath, data=None)
        autoComp = re.search("autocomplete=\"off\"", requester.htmltext,re.IGNORECASE)
        if not autoComp:
            msg = "Autocomplete Off Not Found: " + self.url + self.relPath
            report.info(msg)
        
    # Check if robots.txt is available
    def RobotsTXT(self):
        msg = "Checking Robots.txt File ..."
        report.verbose(msg)
        requester.request(self.url + "/robots.txt", data=None)
        if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
            msg = "Robots.txt Found: " + self.url + "/robots.txt"
            report.low(msg)
        else:
            msg = "No Robots.txt Found"
            report.low(msg)
            

    # Extract error codes and page length from a not existing web page
    def NotExistingURL(self):
        msg = "Requesting Not Existing Pages ..."
        report.verbose(msg)
        self.NotExistingPage = self.url + "/N0WayThatYouAreHere" + time.strftime('%d%m%H%M%S')
        for commExt in self.commExt:
            requester.request(self.NotExistingPage + commExt, data=None)
            self.notValidLen.append(len(requester.htmltext))
            self.notExistingCode = requester.status_code
        self.notValidLen = sorted(set(self.notValidLen))

    # Find interesting directories or files via  dictionary attack
    def CommonFiles(self):
        msg = "Checking interesting directories/files ... "
        report.message(msg)
        self.interFiles = []
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(self.thread_num):
            t = ThreadScanner(self.url, "/", "", self.interFiles, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()

        for extIndex, ext in enumerate(self.commExt):
            # Add all plugins to the queue
            for commFilesIndex, file in enumerate(self.commFiles):
                q.put(file + ext)
                sys.stdout.write("\r" + str((100 * ((len(self.commFiles) * extIndex) + commFilesIndex) / 
                                (len(self.commFiles) * len(self.commExt)))) + "% " + file +  ext + "            ")
                sys.stdout.flush()
            q.join()
            sys.stdout.write("\r")
            sys.stdout.flush()

        for file in self.interFiles:
            msg = self.url + "/" + file
            report.low(msg)

genericchecker = GenericChecks()
