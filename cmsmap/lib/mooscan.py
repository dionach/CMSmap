#! /usr/bin/env python3
import sys, re, hashlib, subprocess, os

# Import Objects
from .initialize import initializer
from .report import report
from .exploitdbsearch import searcher
from .genericchecks import genericchecker
from .bruteforcer import bruter
from .requester import requester


# Import Class
from .threadscanner import ThreadScanner


class MooScan:
    # Scan Moodle site
    def __init__(self):
        self.url = None
        self.usernames = []
        # Plugins can be in /local /blocks /mod
        self.pluginPath = "/local"
        self.pluginsFound = []
        self.notValidLen = []
        self.notExistingCode = 404
        self.confFiles = [line.strip() for line in open(initializer.confFiles)]
        # No plugins for moodle
        #self.plugins = [line.strip() for line in open(initializer.moo_plugins)]

    # Moodle checks
    def Moorun(self):
        msg = "CMS Detection: Moodle"
        report.info(msg)
        searcher.cmstype = "Moodle"
        searcher.pluginPath = self.pluginPath
        self.MooGetLocalFiles()
        self.MooConfigFiles()
        self.MooDefaultFiles()
        self.MooVersion()
        self.MooDirsListing()
    
    # Grab the versions and default files generated at run time
    def MooGetLocalFiles(self):
        self.versions = [line.strip() for line in open(initializer.moo_versions)]
        self.defaultFiles = [line.strip() for line in open(initializer.moo_defaultFiles)]
        self.defaultFolders = [line.strip() for line in open(initializer.moo_defaultFolders)]

    # Find old or temp Moodle config files left on the web root
    def MooConfigFiles(self):
        msg = "Checking Moodle old configuration files ..."
        report.verbose(msg)
        for file in self.confFiles:
            requester.request(self.url + "/config" + file, data=None)
            if requester.status_code == 200 and len(requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/config" + file
                report.high(msg)

    # Find default Moodle files (large number, prompt the user if display them all)
    def MooDefaultFiles(self):
        self.defFilesFound = []
        msg = "Checking Moodle default files ..."
        report.verbose(msg)
        msg = "Moodle Default Files: "
        report.message(msg)
        msg = "Moodle is likely to have a large number of default files"
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
                        self.defFilesFound.append(file)
                sys.stdout.write("\r")
                for file in self.defFilesFound:
                    msg = self.url + file
                    report.info(msg)
    
    # Find Moodle version 
    def MooVersion(self):
        # Check if self.defFilesFound is not empty
        if self.defFilesFound :
            defFileHashes = {}
            top3 = 0
            top3versions = []
            firstmatch = False
            # Create list of Moodle versions {('version': hash_value)}
            for defFile in self.defFilesFound :
                requester.request(self.url + defFile, data=None)
                hash_object = hashlib.sha256(requester.htmltext.encode('utf-8'))
                hash_digest = hash_object.hexdigest()
                defFileHashes[defFile]=hash_digest
            msg = "Checking Moodle version ..."
            report.verbose(msg)
            FNULL = open(os.devnull, 'w')
            p = subprocess.Popen("git -C "+ initializer.cmsmapPath+"/tmp/moodle checkout master -f", stdout=FNULL, stderr=FNULL, shell=True)
            p.communicate()
            # Compare discovered default files with default files against each version of Moodle
            for mver in self.versions :
                msg = "Checking version: "+ mver
                report.verbose(msg)
                matches = 0
                p = subprocess.Popen("git -C "+ initializer.cmsmapPath+"/tmp/moodle checkout tags/"+mver, stdout=FNULL, stderr=FNULL, shell=True)
                p.communicate()
                for defFile, defFileHash in defFileHashes.items() :
                    filepath = initializer.cmsmapPath+"/tmp/moodle"+defFile
                    if os.path.isfile(filepath):
                        f = open(filepath, "rb")
                        hash_object = hashlib.sha256(f.read())
                        hash_digest = hash_object.hexdigest()
                    if hash_digest == defFileHash :
                        matches = matches + 1
                # Margin error of 1 file
                if matches >= (len(defFileHashes)-1) :
                    top3versions.append((mver,matches))
                    firstmatch = True
                if firstmatch :
                    top3 = top3 + 1
                    if top3 == 3 : 
                        top3versions = sorted(top3versions, key=lambda ver: ver[1], reverse=True)
                        msg = "Detected version of Moodle appears to be: "
                        report.info(msg)
                        for moodle_vers in top3versions :
                            msg = str(moodle_vers[0])
                            report.info(msg)
                        break

            p = subprocess.Popen("git -C "+ initializer.cmsmapPath+"/tmp/moodle checkout master -f", stdout=FNULL, stderr=FNULL, shell=True, universal_newlines=True)
            output, error = p.communicate()

    # Find directory listing in default directories and components directories
    def MooDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        report.info(msg)
        report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            genericchecker.DirectoryListing(folder)

mooscan = MooScan()
