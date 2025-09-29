import sys
from logging_setup import setup_logging
from gui import run_app

def main():
    setup_logging()
    sys.exit(run_app("config.yaml"))

if __name__ == "__main__":
    main()