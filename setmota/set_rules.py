#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import urllib.parse
import requests
import socket
import yaml

class TasmotaRule:
    def __init__(self, num=None, rule_data={}):
        self.num = int(num)
        self.rule_name = f'Rule{self.num}'
        self.rule_data=rule_data
        self.rule = rule_data.get('rule')
        self.state = rule_data.get('state')
        self.response = None
        self.set_state = f'{self.rule_name} {self.state}'
        self.success = None
        
    def _check_rule_state(self):
            if self.response.get('State').lower() == self.state.lower() and rule_obj.rule.lower() == self.response.get('Rules').lower():
                self.success = True
            else:
                self.success = False

    def _set_rule(self, pw=None, user=None, ip=None):
        RULE=urllib.parse.quote(f'{self.rule_name} {self.rule}')
        url = f'http://{ip}/cm?user={user}&password={pw}&cmnd={RULE}'
        response = requests.get(url).json()

        RULE_STATE = urllib.parse.quote(f'{self.set_state}')
        url = f'http://{ip}/cm?user={user}&password={pw}&cmnd={RULE_STATE}'
        response = requests.get(url).json()

class TasmotaHost:
    def __init__(self, **kwargs):
        self.ip = kwargs.get('ip')
        self.user = kwargs.get('user')
        self.pw = kwargs.get('pw')
        self.name = kwargs.get('name', '')
        self.rules = {f'Rule{rule_num}': TasmotaRule(num=rule_num, rule_data=rule_data) for rule_num, rule_data in kwargs.get('rules', {}).items()}
        
    def _check_state(self):
        try:
            socket.setdefaulttimeout(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip, 80))
            s.close()
            return True
        except socket.error:
            return False

    def set_rule_status(self):
        identity = f'host {self.name} {self.ip}'
        if self._check_state():
            for rule_name, rule_obj in self.rules.items():
                response = requests.get(f'http://{self.ip}/cm?user={self.user}&password={self.pw}&cmnd={rule_name}').json()
                rule_obj.response = response.get(rule_name)
                rule_obj._set_rule(user=self.user, ip=self.ip, pw=self.pw)
                # rule_obj._check_rule_state()
                # if rule_obj.success==False:
                #     rule_obj._set_rule(user=self.user, ip=self.ip, pw=self.pw)
                #     rule_obj._check_rule_state()
            print(f'{identity}: set rules')
        else:
            print(f'{identity}: offline. skipping.')
            
class TasmotaConfigParser:
    def __init__(self, config_file):
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
            
        self.defaults = config.get('DEFAULTS', {})
        self.hosts = [TasmotaHost(**{**host_data, **self.defaults, 'name':name}) for name, host_data in config.get('HOSTS', {}).items()]
    
    def apply(self):
        for host in self.hosts:
            host.set_rule_status()

if __name__ == '__main__':
    pass
    self = TasmotaConfigParser('../config.yml')
