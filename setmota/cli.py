#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI
"""
import os
import sys
import argparse
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from setmota.set_rules import *

def main():
    parser = argparse.ArgumentParser(description='Tasmota Rule Setter CLI')
    parser.add_argument('config', help='Specify the configuration file')
    args = parser.parse_args()
    
    Tasmota = TasmotaConfigParser(args.config)

    Tasmota.apply()