#!/usr/bin/env python3
import os, sys, platform

from .initialize import initializer


class Report:

    def __init__(self):
        self.fn = ""
        self.log = ' '.join(sys.argv)
        self.col()

    def col(self):
        if sys.stdout.isatty() and platform.system() != "Windows":
            self.green = '\033[32m'
            self.blue = '\033[94m'
            self.red = '\033[31m'
            self.brown = '\033[33m'
            self.grey = '\033[90m'
            self.orange = '\033[38;5;208m'
            self.yellow = '\033[93m'
            self.end = '\033[0m'

        else:  # Disalbing col for windows and pipes
            self.green = ""
            self.orange = ""
            self.blue = ""
            self.red = ""
            self.brown = ""
            self.grey = ""
            self.yellow = ""
            self.end = ""

    def info(self, msg):
        self.WriteTextFile("[I] " + msg)
        msg = self.green + "[I] " + self.end + msg
        print(msg)

    def low(self, msg):
        self.WriteTextFile("[L] " + msg)
        msg = self.yellow + "[L] " + self.end + msg
        print(msg)

    def medium(self, msg):
        self.WriteTextFile("[M] " + msg)
        msg = self.orange + "[M] " + self.end + msg
        print(msg)

    def high(self, msg):
        self.WriteTextFile("[H] " + msg)
        msg = self.red + "[H] " + self.end + msg
        print(msg)

    def status(self, msg):
        self.WriteTextFile("[-] " + msg)
        msg = self.blue + "[-] " + self.end + msg
        print(msg)

    def message(self, msg):
        msg = "[-] " + msg
        print(msg)
        self.WriteTextFile(msg)

    def error(self, msg):
        self.WriteTextFile("[ERROR] " + msg)
        msg = self.red + "[ERROR] " + self.end + msg
        print(msg)

    def verbose(self, msg):
        if initializer.verbose:
            self.WriteTextFile("[v] " + msg)
            msg = self.grey + "[v] " + self.end + msg
            print(msg)

    def WriteTextFile(self, msg):
        if initializer.output:
            self.log += "\n" + msg
            f = open(os.path.join(os.getcwd(), self.fn), "w")
            f.write(self.log)
            f.close()

    def WriteHTMLFile(self):
        pass


report = Report()
