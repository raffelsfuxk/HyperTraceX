#!/usr/bin/env python3
"""Structured Logging System for HyperTraceX Framework."""

import sys
import logging
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler

def setup_logging(log_dir: Path, log_level: str = "INFO") -> logging.Logger:
    """Configure professional logging with rotation."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"tracex_{datetime.now():%Y%m%d_%H%M%S}.log"
    
    logger = logging.getLogger("HyperTraceX")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    fh = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=5)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(ch)
    
    return logger

def get_logger(name: str = "HyperTraceX") -> logging.Logger:
    return logging.getLogger(name)
