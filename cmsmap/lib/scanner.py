#! /usr/bin/env python3
import sys

# Import Objects
from urllib.parse import urlparse
from .initialize import initializer
from .wpscan import wpscan
from .jooscan import jooscan
from .druscan import druscan
from .mooscan import mooscan
from .report import report
from .genericchecks import genericchecker
from .requester import requester
from .bruteforcer import bruter


class Scanner:
    # Main class for scanning the website
    def __init__(self):
        self.headers = initializer.headers
        self.url = None
        self.force = None
        self.file = None
        self.notExistingCode = 404
        self.notValidLen = []

    # Execute some initial checks and then attempt to identify the type of CMS
    def RunScanner(self):
        wpscan.url = jooscan.url = druscan.url = mooscan.url = initializer.url
        genericchecker.CheckURL()
        genericchecker.NotExistingURL()
        wpscan.notExistingCode = jooscan.notExistingCode = druscan.notExistingCode = genericchecker.notExistingCode
        wpscan.notValidLen = jooscan.notValidLen = druscan.notValidLen = genericchecker.notValidLen
        genericchecker.HTTPSCheck()
        genericchecker.HeadersCheck()
        genericchecker.RobotsTXT()
        if self.force is None:
            self.FindCMSType()
        else:
            self.ForceCMSType()

    # Force the execution of the scan based on the user's input
    def ForceCMSType(self):
        if self.force == 'W':
            if initializer.BruteForcingAttack :
                bruter.force = 'W'
                bruter.Start()    
            else :
                wpscan.WPrun()
        elif self.force == 'J':
            if initializer.BruteForcingAttack :
                bruter.force = 'J'
                bruter.Start()    
            else :
                jooscan.Joorun()
        elif self.force == 'D':
            if initializer.BruteForcingAttack :
                bruter.force = 'D'
                bruter.Start()    
            else :
                druscan.Drurun()
        elif self.force == 'M':
            mooscan.Moorun()
        else:
            msg = "Not Valid Option Provided: use (W)ordpress, (J)oomla, (D)rupal"
            report.error(msg)
            sys.exit(1)

    # Attempt to identify the type of CMS based on the configuration file
    def FindCMSType(self):
        msg = "Detecting type of CMS ..."
        report.verbose(msg)
        if self.force is None:
            requester.request(self.url+ "/wp-config.php", data=None)
            if (requester.status_code == 403 or 
                requester.status_code == 200) and len(requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'W'
            else:
                msg = "WordPress Config File Not Found: " + self.url + "/wp-config.php"
                report.verbose(msg)
            # Joomla
            requester.request(self.url+ "/configuration.php", data=None)
            if (requester.status_code == 403 or 
                requester.status_code == 200) and len(requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'J'
            else:
                msg = "Joomla Config File Not Found: " + self.url + "/configuration.php"
                report.verbose(msg)
            # Drupal
            requester.request(self.url+ "/sites/default/settings.php", data=None)
            if (requester.status_code == 403 or 
                requester.status_code == 200) and len(requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'D'
            pUrl = urlparse(self.url)
            netloc = pUrl.netloc.lower()
            requester.request(self.url + "/sites/" + netloc + "/settings.php", data=None)
            if (requester.status_code == 403 or 
                requester.status_code == 200) and len(requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'D'
            else:
                msg = "Drupal Config File Not Found: " + self.url + "/sites/default/settings.php"
                report.verbose(msg)
            # Moodle
            requester.request(self.url+ "/config.php", data=None)
            if (requester.status_code == 403 or 
                requester.status_code == 200) and len(requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'M'
            else:
                msg = "Moodle Config File Not Found: " + self.url + "/config.php"
                report.verbose(msg)
            # CMS Detection has failed
            if self.force is None:
                msg = "CMS detection failed :("
                report.error(msg)
                msg = "Use -f to force CMSmap to scan (W)ordpress, (J)oomla or (D)rupal"
                report.error(msg)
                sys.exit(1)
            else:
                self.ForceCMSType()
        else:
            msg = "CMSmap forced to scan: " + self.force
            report.verbose(msg)

scanner = Scanner()
