#! /usr/bin/env python3
import sys, re, queue, time

# Import Objects
from .initialize import initializer
from .report import report
from .exploitdbsearch import searcher
from .bruteforcer import bruter
from .genericchecks import genericchecker
from .requester import requester

# Import Class
from .threadscanner import ThreadScanner


class DruScan:
    # Scan Drupal site
    def __init__(self):
        self.url = None
        self.notExistingCode = 404
        self.notValidLen = []
        self.pluginPath = "/modules/"
        self.confFiles = [line.strip() for line in open(initializer.confFiles)]
        self.usernames = []
        self.pluginsFound = []
        self.plugins = [line.strip() for line in open(initializer.dru_plugins)]

    # Drupal checks
    def Drurun(self):
        msg = "CMS Detection: Drupal"
        report.info(msg)
        searcher.cmstype = "Drupal"
        searcher.pluginPath = self.pluginPath
        self.DruGetLocalFiles()
        self.DruVersion()
        self.DruCurrentTheme()
        self.DruConfigFiles()
        self.DruViews()
        self.DruBlog()
        self.DruQUser()
        bruter.usrlist = self.usernames
        bruter.pswlist = initializer.weakpsw
        if bruter.dictattack is not None: bruter.Drurun()
        genericchecker.AutocompleteOff(self.quser)
        self.DruDefaultFiles()
        if initializer.FullScan: genericchecker.CommonFiles()
        self.DruForgottenPassword()
        self.DruModulesIndex()
        self.DruModules()
        self.DruModulesVersion()
        searcher.query = self.pluginsFound
        searcher.OfflinePlugins()
        self.DruDirsListing()

    # Grab the small plugins, versions and default files generated at run time
    def DruGetLocalFiles(self):
        self.plugins_small = [line.strip() for line in open(initializer.dru_plugins_small)]
        self.versions = [line.strip() for line in open(initializer.dru_versions)]
        self.defaultFiles = [line.strip() for line in open(initializer.dru_defaultFiles)]
        self.defaultFolders = [line.strip() for line in open(initializer.dru_defaultFolders)]

    # Find Drupal version and check it on exploit-db
    def DruVersion(self):
        msg = "Checking Drupal version ..."
        report.verbose(msg)
        requester.request(self.url + '/CHANGELOG.txt', data=None)
        regex = 'Drupal (\d+\.\d+),'
        pattern = re.compile(regex)
        version = re.findall(pattern, requester.htmltext)
        if version:
            msg = "Drupal Version: " + version[0]
            report.info(msg)
            if version[0] in self.versions:
                for ver in self.versions:
                    searcher.query = ver
                    searcher.OfflineCore()
                    if ver == version[0]:
                        break

    # Find current Drupal theme and check it on exploit-db
    def DruCurrentTheme(self):
        msg = "Checking Drupal theme"
        report.verbose(msg)
        requester.request(self.url, data=None)
        DruTheme = re.findall("/themes/(.+?)/", requester.htmltext, re.IGNORECASE)
        if DruTheme:
            self.Drutheme = DruTheme[0]
            msg = "Drupal Theme: " + self.Drutheme
            report.info(msg)
            searcher.query = self.Drutheme
            searcher.OfflineTheme()

    # Find old or temp Drupal conf files left on the web root
    def DruConfigFiles(self):
        msg = "Checking Drupal old config files"
        report.verbose(msg)
        for file in self.confFiles:
            requester.request(self.url + "/sites/default/settings" + file, data=None)
            if requester.status_code  == 200 and len(requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/sites/default/settings" + file
                report.high(msg)

    # Find default Drupal files (large number, prompt the user if display them all)
    def DruDefaultFiles(self):
        msg = "Checking Drupal default files"
        report.verbose(msg)
        self.defFilesFound = []
        msg = "Drupal Default Files: "
        report.message(msg)
        msg = "Drupal is likely to have a large number of default files"
        report.message(msg)
        msg = "Would you like to list them all?"
        report.message(msg)
        if not initializer.default:
            if input("[y/N]: ").lower().startswith('y'):
                # Check for default files
                for r, file in enumerate(self.defaultFiles):
                    requester.request(self.url + file, data=None)
                    sys.stdout.write("\r" + str(int(100 * int(r + 1) / len(self.defaultFiles))) + "%")
                    sys.stdout.flush()
                    if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
                        self.defFilesFound.append(self.url + file)
                sys.stdout.write("\r")
                for file in self.defFilesFound:
                    msg = file
                    report.info(msg)

    # Find Drupal users via the View Module
    def DruViews(self):
        self.views = "/?q=admin/views/ajax/autocomplete/user/"
        if not initializer.disableCleanURLs :
            self.views = self.views.replace("?q=","")
        self.alphanum = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        msg = "Enumerating Drupal Usernames via \"Views\" Module..."
        report.message(msg)
        requester.noredirect(self.url + "/?q=admin/views/ajax/autocomplete/user/NotExisingUser1234!", data=None) 
        #If NotExisingUser1234 returns [], then enumerate users
        if requester.htmltext == '[]':
            msg = "\"Views\" Module vulnerable to user enumeration"
            report.medium(msg)
            for letter in self.alphanum:
                requester.noredirect(self.url + self.views + letter, data=None)
                regex = '"(.+?)"'
                pattern = re.compile(regex)
                self.usernames = self.usernames + re.findall(pattern, requester.htmltext)
            self.usernames = sorted(set(self.usernames))
            for user in self.usernames:
                msg = user
                report.info(msg)

    # Find Drupal users checking the first 50 authors blogs
    def DruBlog(self):
        self.blog = "/?q=blog/"
        if not initializer.disableCleanURLs :
            self.blog = self.blog.replace("?q=","")
        requester.request(self.url + self.blog, data=None)
        if requester.status_code == 200: 
            msg = "Enumerating Drupal Usernames via \"Blog\" Module..."
            report.message(msg)
            for blognum in range(1, 50):
                requester.request(self.url + self.blog + str(blognum), data=None)
                regex = "<title>(.+?)\'s"
                pattern = re.compile(regex)
                user = re.findall(pattern, requester.htmltext)
                self.usernames = self.usernames + user
                if user:
                    msg = user[0]
                    report.info(msg)
            self.usernames = sorted(set(self.usernames))

    def DruQUser(self):
        self.quser = "/?q=user/"
        if not initializer.disableCleanURLs :
            self.quser = self.quser.replace("?q=","")
        msg = "Enumerating Drupal Usernames via \""+self.quser+"\"..."
        report.message(msg)
        for usernum in range(1, 50):
            requester.request(self.url + self.quser + str(usernum), data=None)
            regex = "users\/(.+?)\?destination"
            pattern = re.compile(regex)
            user = re.findall(pattern, requester.htmltext)
            self.usernames = self.usernames + user
            if user:
                msg = user[0]
                report.info(msg)
        self.usernames = sorted(set(self.usernames))

    # Check if it is possible to enumerate users via Forgotten password functionality
    def DruForgottenPassword(self):
        self.forgottenPsw = "/?q=user/password"
        if not initializer.disableCleanURLs :
            self.forgottenPsw = self.forgottenPsw.replace("?q=","")
        msg = "Checking Drupal forgotten password ..."
        report.verbose(msg)
        # Username Enumeration via Forgotten Password
        self.postdata = {"name": "N0t3xist!1234", "form_id": "user_pass"}
        # HTTP POST Request
        requester.request(self.url + self.forgottenPsw, data=self.postdata)
        #print "[*] Trying Credentials: "+user+" "+pwd
        if re.findall(re.compile('Sorry,.*N0t3xist!1234.*is not recognized'), requester.htmltext):
            msg = "Forgotten Password Allows Username Enumeration: " + self.url + self.forgottenPsw
            report.info(msg)
            report.WriteTextFile(msg)

    # Find directory listing in default directories and module directories
    def DruDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        report.info(msg)
        report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            genericchecker.DirectoryListing(folder)
        for plugin in self.pluginsFound:
            genericchecker.DirectoryListing('/modules/' + plugin)

    # Find modules checking the source code of the main page
    def DruModulesIndex(self):
        msg = "Checking Drupal mudules in the index page"
        report.verbose(msg)
        requester.request(self.url, data=None)
        self.pluginsFound = re.findall(
            re.compile('/modules/(.+?)/'), requester.htmltext)
        self.pluginsFound = sorted(set(self.pluginsFound))

    # Template to find plugins version
    # Convert DruPluginsFound in a dictionary
    def DruModulesVersion(self):
        self.pluginsFoundVers = {}
        for pluginFound in self.pluginsFound:
            self.pluginsFoundVers[pluginFound] = None
        self.pluginsFound = self.pluginsFoundVers
    
    # Find modules via dictionary attack
    def DruModules(self):
        msg = "Search Drupal Modules ..."
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
        for r, i in enumerate(self.plugins):
            q.put(i)
            sys.stdout.write("\r" + str(100 * int(r + 1) / len(self.plugins)) + "%")
            sys.stdout.flush()
        q.join()
        sys.stdout.write("\r")

druscan = DruScan()
