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
    # Optionales Argument für ein Kommando mit einem Wert
    parser.add_argument(
        "--cmd",
        help="Specify a Tasmota command and its value from https://tasmota.github.io/docs/Commands/#control",
        nargs=3,
        metavar=("HOSTNAME as in config", "COMMAND", "VALUE"),
        required=False
    )
    args = parser.parse_args()
    
    Tasmota = TasmotaConfigParser(args.config)

    if args.cmd:
        hostname, command, value = args.cmd
        host = Tasmota.get_host(hostname)
        auth = host.get_auth()
        cmd = get_command_class(command)(parameters=value)
        tasmota_command = TasmotaCommand(cmd, auth=auth)
        print(tasmota_command.execute())
    else:
        Tasmota.apply()