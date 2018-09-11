#! /usr/bin/env python3
import os, configparser

class Initialize:

    def __init__(self):
        self.url = None
        self.netloc = None
        self.scheme = None
        self.verbose = False
        self.default = False
        self.BruteForcingAttack = False
        self.CrackingPasswords = False
        self.FullScan = False
        self.NoExploitdb = False
        self.disableCleanURLs = False # https://www.drupal.org/docs/8/clean-urls-in-drupal-8
        self.cmsmapPath = os.path.join(os.path.dirname(__file__), os.pardir)
        self.cmsmapPath = os.path.normpath(os.path.join(os.path.dirname(__file__), os.pardir))
        self.ospath = self.cmsmapPath
        self.output = False
        self.threads = 5
        self.forceCMSmapUpdateType = None
        self.forceCMSmapUpdate = False
        self.weakpsw = ['password', 'admin', '123456', 'Password1']
        self.config = configparser.ConfigParser()
        self.config.read(os.path.join(self.cmsmapPath, "cmsmap.conf"))
        self.ParseConfigFile()

    def ParseConfigFile(self):
        # General
        self.agent = self.config.get("general", "user-agent")
        self.headers = {'User-Agent': self.agent}
        self.wordlist = os.path.join(self.cmsmapPath, self.config.get("general", "wordlist"))
        self.dataPath = os.path.join(self.cmsmapPath, self.config.get("general", "dataPath"))
        self.commFiles = os.path.join(self.cmsmapPath, self.config.get("general", "common_files"))
        self.confFiles = os.path.join(self.cmsmapPath, self.config.get("general", "conf_extensions"))

        # Wordpress
        self.wp_plugins = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_plugins"))
        self.wp_plugins_small = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_plugins_small"))
        self.wp_themes_small = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_themes_small"))
        self.wp_themes = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_themes"))
        self.wp_versions = os.path.join(self.cmsmapPath, self.config.get("wordpress","wp_versions"))
        self.wp_timthumbs = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_timthumbs"))
        self.wp_defaultFiles = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_defaultFiles"))
        self.wp_defaultFolders = os.path.join(self.cmsmapPath, self.config.get("wordpress", "wp_defaultFolders"))
        # Joomla
        self.joo_plugins = os.path.join(self.cmsmapPath, self.config.get("joomla", "joo_plugins"))
        self.joo_plugins_small = os.path.join(self.cmsmapPath, self.config.get("joomla", "joo_plugins_small"))
        self.joo_defaultFiles = os.path.join(self.cmsmapPath, self.config.get("joomla", "joo_defaultFiles"))
        self.joo_defaultFolders = os.path.join(self.cmsmapPath, self.config.get("joomla", "joo_defaultFolders"))
        self.joo_versions = os.path.join(self.cmsmapPath, self.config.get("joomla", "joo_versions"))
        # Drupal
        self.dru_plugins = os.path.join(self.cmsmapPath, self.config.get("drupal", "dru_plugins"))
        self.dru_plugins_small = os.path.join(self.cmsmapPath, self.config.get("drupal", "dru_plugins_small"))
        self.dru_defaultFiles = os.path.join(self.cmsmapPath, self.config.get("drupal", "dru_defaultFiles"))
        self.dru_defaultFolders = os.path.join(self.cmsmapPath, self.config.get("drupal", "dru_defaultFolders"))
        self.dru_versions = os.path.join(self.cmsmapPath, self.config.get("drupal", "dru_versions")) 
        # Moodle
        #self.moo_plugins = os.path.join(self.cmsmapPath, self.config.get("moodle", "moo_plugins"))
        #self.moo_plugins_small = os.path.join(self.cmsmapPath, self.config.get("moodle", "moo_plugins_small"))
        self.moo_defaultFiles = os.path.join(self.cmsmapPath, self.config.get("moodle", "moo_defaultFiles"))
        self.moo_defaultFolders = os.path.join(self.cmsmapPath, self.config.get("moodle", "moo_defaultFolders"))
        self.moo_versions = os.path.join(self.cmsmapPath, self.config.get("moodle", "moo_versions"))
        
        # ExploitDB
        self.edbtype = self.config.get("exploitdb", "edbtype")
        self.edbpath = os.path.join(os.path.normpath(self.config.get("exploitdb", "edbpath")), "")


initializer = Initialize()
