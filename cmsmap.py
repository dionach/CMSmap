#!/usr/bin/python3
import signal, sys

from cmsmap.main import main
from cmsmap.lib.report import report

def exit(signum, frame):
    signal.signal(signal.SIGINT, original_sigint)
    try:
        msg = "Interrupt caught. CMSmap paused. Do you really want to exit?"
        report.error(msg)
        if input("[y/N]: ").lower().startswith('y'):
            msg = "Bye! Quitting.. "
            report.message(msg)
            sys.exit(1)
    except KeyboardInterrupt:
        msg = "Bye! Quitting.."
        report.message(msg)
        sys.exit(1)
    signal.signal(signal.SIGINT, exit)

if __name__ == "__main__":
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit)
    main()
