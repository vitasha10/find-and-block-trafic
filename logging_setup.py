import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = RotatingFileHandler(os.path.join(log_dir, "app.log"), maxBytes=5_000_000, backupCount=5)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    det = logging.getLogger("detector")
    sniff = logging.getLogger("sniffer")
    fw = logging.getLogger("firewall")
    gui = logging.getLogger("gui")
    return logger