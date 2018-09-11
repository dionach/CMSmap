#! /usr/bin/env python3
import sys, re, queue, time

# Import Object
from .initialize import initializer
from .report import report
from .exploitdbsearch import searcher
from .bruteforcer import bruter
from .genericchecks import genericchecker
from .requester import requester

# Import Class
from .threadscanner import ThreadScanner

class WPScan:
    # Scan WordPress site
    def __init__(self):
        self.url = None
        self.currentVer = None
        self.latestVer = None
        self.pluginPath = "/wp-content/plugins/"
        self.themePath = "/wp-content/themes/"
        self.feed = "/?feed=rss2"
        self.author = "/?author="
        self.forgottenPsw = "/wp-login.php?action=lostpassword"
        self.usernames = []
        self.pluginsFound = []
        self.timthumbsFound = []
        self.notValidLen = []
        self.XMLRPCEnable = True
        self.theme = None
        self.notExistingCode = 404
        self.confFiles = [line.strip() for line in open(initializer.confFiles)]
        self.plugins = [line.strip() for line in open(initializer.wp_plugins)]
        self.themes = [line.strip() for line in open(initializer.wp_themes)]
        self.themes_small = [line.strip() for line in open(initializer.wp_themes_small)]
        self.timthumbs = [line.strip() for line in open(initializer.wp_timthumbs)]

    # WordPress checks
    def WPrun(self):
        msg = "CMS Detection: WordPress"
        report.info(msg)
        searcher.cmstype = "Wordpress"
        searcher.pluginPath = self.pluginPath
        self.WPGetLocalFiles()
        self.WPVersion()
        self.WPCurrentTheme()
        self.WPConfigFiles()
        self.WPHello()
        self.WPFeed()
        self.WPAuthor()
        bruter.usrlist = self.usernames
        bruter.pswlist = initializer.weakpsw
        self.WPXMLRPC_check()
        if self.XMLRPCEnable:
            if bruter.dictattack is not None: bruter.WPXMLRPC_brute()
            self.WPXMLRPC_pingback()
            self.WPXMLRPC_BF()
        elif bruter.dictattack is not None:
            bruter.WPrun()
        self.WPForgottenPassword()
        genericchecker.AutocompleteOff('/wp-login.php')
        self.WPDefaultFiles()
        if initializer.FullScan: genericchecker.CommonFiles()
        self.WPpluginsIndex()
        self.WPplugins()
        self.WPpluginsVersion()
        searcher.query = self.pluginsFound
        searcher.OfflinePlugins()
        if initializer.FullScan: self.WPTimThumbs()
        self.WPDirsListing()

    # Grab the small plugins, versions and default files generated at run time
    def WPGetLocalFiles(self):
        self.plugins_small = [line.strip() for line in open(initializer.wp_plugins_small)]
        self.versions = [line.strip() for line in open(initializer.wp_versions)]
        self.defaultFiles = [line.strip() for line in open(initializer.wp_defaultFiles)]
        self.defaultFolders = [line.strip() for line in open(initializer.wp_defaultFolders)]

    # Find WordPress version and check it on exploit-db
    def WPVersion(self):
        msg = "Checking WordPress version ..."
        report.verbose(msg)
        requester.request(self.url + '/readme.html', data=None)
        regex = '<br />.* (\d+\.\d+[\.\d+]*)\n</h1>'
        pattern = re.compile(regex)
        self.currentVer = re.findall(pattern, requester.htmltext)
        if self.currentVer:
            msg = "Wordpress Version: " + self.currentVer[0]
            report.info(msg)
        else:
            requester.request(self.url, data=None)           
            self.currentVer = re.findall('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"', requester.htmltext)
            if self.currentVer:
                msg = "Wordpress Version: " + self.currentVer[0]
                report.info(msg)
        if self.currentVer:
            if self.currentVer[0] in self.versions:
                for ver in self.versions:
                    searcher.query = ver
                    searcher.OfflineCore()
                    if ver == self.currentVer[0]:
                        break

    # Find WordPress theme and check it on exploit-db
    def WPCurrentTheme(self):
        msg = "Checking WordPress theme ..."
        report.verbose(msg)
        requester.request(self.url, data=None)
        regex = '/wp-content/themes/(.+?)/'
        pattern = re.compile(regex)
        CurrentTheme = re.findall(pattern, requester.htmltext)
        if CurrentTheme:
            self.theme = CurrentTheme[0]
            msg = "Wordpress Theme: " + self.theme
            report.info(msg)
            searcher.query = self.theme
            searcher.OfflineTheme()

    # Find old or temp WordPress config files left on the web root
    def WPConfigFiles(self):
        msg = "Checking old WordPress config files ..."
        report.verbose(msg)
        for file in self.confFiles:
            requester.request(self.url + "/wp-config" + file, data=None)
            if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/wp-config" + file
                report.high(msg)

    # Find default WordPress files
    def WPDefaultFiles(self):
        self.defFilesFound = []
        msg = "Checking WordPres default files..."
        report.verbose(msg)
        msg = "Default WordPress Files:"
        report.message(msg)
        for file in self.defaultFiles:
            requester.request(self.url + file, data=None)
            if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
                self.defFilesFound.append(self.url + file)
        for file in self.defFilesFound:
            msg = file
            report.info(msg)

    # Find WordPress users checking the dc:creator field in Feed function
    def WPFeed(self):
        msg = "Enumerating Wordpress usernames via \"Feed\" ..."
        report.verbose(msg)
        requester.request(self.url + self.feed, data=None) 
        wpUsers = re.findall("<dc:creator>[<!\[CDATA\[]*(.+?)[\]\]>]*</dc:creator>",
            requester.htmltext)
        if wpUsers:
            self.usernames = wpUsers + self.usernames
            self.usernames = sorted(set(self.usernames))

    # Find WordPress users checking the first 50 authors blogs
    def WPAuthor(self):
        msg = "Enumerating Wordpress usernames via \"Author\" ..."
        report.verbose(msg)
        for user in range(1, 50):
            requester.request(self.url + self.author + str(user), data=None)
            wpUser = re.findall("author author-(.+?) ", requester.htmltext, re.IGNORECASE)
            if wpUser: self.usernames = wpUser + self.usernames
            wpUser = re.findall("Posts by (.+?) Feed", requester.htmltext, re.IGNORECASE)
            if wpUser: self.usernames = wpUser + self.usernames
        self.usernames = sorted(set(self.usernames))
        # if users are found, print them (it includes the users found by WPFeed)
        if self.usernames:
            msg = "WordPress usernames identified: "
            report.message(msg)
            for user in self.usernames:
                msg = user
                report.medium(msg)

    # Check it is possible to enumerate users via Forgotten password functionality
    def WPForgottenPassword(self):
        msg = "Checking WordPress forgotten password ..."
        report.verbose(msg)
        # Use an invalid, not-existing, not-registered user
        self.postdata = {"user_login": "N0t3xist!1234"}
        requester.request(self.url + self.forgottenPsw, data=self.postdata)  
        if re.findall(re.compile('Invalid username'), requester.htmltext):
            msg = "Forgotten Password Allows Username Enumeration: " + self.url + self.forgottenPsw
            report.info(msg)

    # Find full path via the default hello plugin
    def WPHello(self):
        requester.request(self.url + "/wp-content/plugins/hello.php", data=None) 
        fullPath = re.findall(re.compile('Fatal error.*>/(.+?/)hello.php'), requester.htmltext)
        if fullPath:
            msg = "Wordpress Hello Plugin Full Path Disclosure: " + "/" + fullPath[0] + "hello.php"
            report.low(msg)        

    # Find directory listing in default directories and plugin directories
    def WPDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        report.info(msg)
        report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            genericchecker.DirectoryListing(folder)
        if self.theme:
            genericchecker.DirectoryListing('/wp-content/themes/' + self.theme)
        for plugin in self.pluginsFound:
            genericchecker.DirectoryListing('/wp-content/plugins/' + plugin)

    # Find plugins checking the source code of the main page
    def WPpluginsIndex(self):
        msg = "Checking WordPress plugins in the index page"
        report.verbose(msg)
        requester.request(self.url, data=None) 
        self.pluginsFound = re.findall(re.compile('/wp-content/plugins/(.+?)/'), requester.htmltext)

    # Find plugins via a dictionary attack
    def WPplugins(self):
        msg = "Searching Wordpress Plugins ..."
        report.message(msg)
        if not initializer.FullScan: self.plugins = self.plugins_small
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, self.pluginPath, "/", self.pluginsFound, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()
        # Add all plugins to the queue
        for i in self.plugins:
            q.put(i)
        while not q.empty() :
            sys.stdout.write("\r"+str(int((len(self.plugins) - q.qsize()) * 1.0 / len(self.plugins) * 100)) + "%")
            sys.stdout.flush()
            time.sleep(1)
        q.join()
        sys.stdout.write("\r")
        self.pluginsFound = sorted(set(self.pluginsFound))

    # self.pluginsFound are now a dictionary {"plugin_name":"plugin_version"}
    # Attempt to find plugins version
    def WPpluginsVersion(self):
        self.pluginsFoundVers = {}
        for pluginFound in self.pluginsFound:
            requester.request(self.url+self.pluginPath+pluginFound+"/readme.txt", data=None)
            pluginVer = re.findall('Stable tag: (\d+\.\d+[\.\d+]*)', requester.htmltext)
            # Add plugin version
            if pluginVer : 
                self.pluginsFoundVers[pluginFound] = pluginVer[0]
            else:
                # Match has not been found
                self.pluginsFoundVers[pluginFound] = None
        self.pluginsFound = self.pluginsFoundVers

    # Find WordPress TimThumbs via a dictionary attack
    def WPTimThumbs(self):
        msg = "Searching Wordpress TimThumbs ..."
        report.message(msg)
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, "/", "", self.timthumbsFound, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()
        # Add all plugins to the queue
        for r, i in enumerate(self.timthumbs):
            q.put(i)
        q.join()
        sys.stdout.write("\r")
        if self.timthumbsFound:
            for timthumbsFound in self.timthumbsFound:
                msg = self.url + "/" + timthumbsFound
                report.medium(msg)
            msg = " Timthumbs Potentially Vulnerable to File Upload: http://www.exploit-db.com/wordpress-timthumb-exploitation"
            report.medium(msg)

    # Find other WordPress installed via a dictionary attack
    def WPThemes(self):
        msg = "Searching Wordpress Themes ..."
        report.message(msg)
        if not initializer.FullScan: self.themes = self.themes_small
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, self.themePath, "/", self.themesFound, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()
        # Add all theme to the queue
        for r, i in enumerate(self.themes):
            q.put(i)
            sys.stdout.write("\r" + str(100 * int(r + 1) / len(self.themes)) + "%")
            sys.stdout.flush()
        q.join()
        sys.stdout.write("\r")
        for themesFound in self.themesFound:
            msg = themesFound
            report.info(msg)

    # Check if XML-RPC services are enabled
    def WPXMLRPC_check(self):
        msg = "Checking if XML-RPC services are enabled ..."
        report.verbose(msg)
        self.postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params>
                        <param><value><string>ThisIsATest</string></value></param>
                        <param><value><string>ThisIsATest</string></value></param></params></methodCall>
                        '''
        requester.request(self.url + '/xmlrpc.php', data = self.postdata)
        if re.search('<value><string>XML-RPC services are disabled', requester.htmltext):
            msg = "XML-RPC services are disabled"
            report.verbose(msg)
            self.XMLRPCEnable = False
        else:
            msg = "XML-RPC services are enabled"
            report.medium(msg)

    # Check if the XML-RPC Pingback is enabled
    def WPXMLRPC_pingback(self):
        msg = "Checking XML-RPC Pingback Vulnerability ..."
        report.verbose(msg)
        self.postdata = '''<methodCall><methodName>pingback.ping</methodName><params>
                        <param><value><string>http://N0tB3th3re0484940:22/</string></value></param>
                        <param><value><string>''' + self.url + '''</string></value></param>
                        </params></methodCall>'''
        requester.request(self.url + '/xmlrpc.php', data = self.postdata)
        if re.search('<name>16</name>', requester.htmltext):
            msg = "Website vulnerable to XML-RPC Pingback Force Vulnerability"
            report.low(msg)

    # Check if it is possible to brute-froce the logins via XML-RPC
    def WPXMLRPC_BF(self):
        msg = "Checking XML-RPC Brute Force Vulnerability ..."
        report.verbose(msg)
        self.postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params>
                        <param><value><string>admin</string></value></param>
                        <param><value><string></string></value></param>
                        </params></methodCall>'''
        requester.request(self.url + '/xmlrpc.php', data = self.postdata)
        if re.search('<int>403</int>', requester.htmltext):
            msg = "Website vulnerable to XML-RPC Brute Force Vulnerability"
            report.medium(msg)
            if self.currentVer:
                if self.currentVer[0] < '4.4':
                    msg = "Website vulnerable to XML-RPC Amplification Brute Force Vulnerability"
                    report.medium(msg)

wpscan = WPScan()
