#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import urllib.parse
import requests
import socket
import yaml
from pydantic import BaseModel, Field, ValidationError, root_validator, validator
from typing import Union, Literal
import re

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
    
    def get_auth(self):
        return WebAuth(user=self.user, ip=self.ip, pw=self.pw)

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

    def get_host(self, name):
        for host in self.hosts:
            if host.name == name:
                return host
        raise ValueError(f"Host with name '{name}' not found.")

###commands
class GeneralCommand(BaseModel):
    """
    Basisklasse für Tasmota-Befehle. Verwendet Pydantic für die Validierung.
    """
    command: str = Field(..., description="Der Name des Befehls.")
    parameters: str = Field("", description="Parameter für den Befehl, falls erforderlich.")

    def __str__(self):
        """
        Gibt den Befehl in der Form 'command parameters' zurück.
        """
        return f"{self.command} {self.parameters}".strip()

class PowerCommand(GeneralCommand):
    """
    Klasse für den Power-Befehl mit erweiterter Validierung.
    """
    command: Literal["Power"] = Field(description="Befehl für die Steuerung des Power-Zustands.")
    parameters: Union[int, str] = Field(
        ..., 
        description="Power-Zustand: 0/off/false, 1/on/true, 2/toggle, 3/blink, 4/blinkoff."
    )

    @root_validator(pre=True)
    def validate_parameters(cls, values):
        """
        Validiert die Eingabe für den Parameter und konvertiert alternative Werte in Standardwerte.
        """
        param = str(values.get("parameters", "")).strip().lower()

        # Mapping alternativer Eingaben auf Standardwerte
        param_map = {
            "0": 0, "off": 0, "false": 0,
            "1": 1, "on": 1, "true": 1,
            "2": 2, "toggle": 2,
            "3": 3, "blink": 3,
            "4": 4, "blinkoff": 4,
        }

        if param not in param_map:
            raise ValueError(f"Ungültiger Wert für 'parameters': {values['parameters']}. "
                             "Erlaubt sind: 0/off/false, 1/on/true, 2/toggle, 3/blink, 4/blinkoff.")

        # Konvertiere den Parameter in den Standardwert
        values["parameters"] = param_map[param]
        return values

class WebAuth(BaseModel):
    """
    Pydantic-Modell zur Validierung der Authentifizierungsdaten für Tasmota-Webschnittstelle.
    """
    user: str = Field(..., description="Benutzername für die Web-Authentifizierung.")
    pw: str = Field(..., description="Passwort für die Web-Authentifizierung.")
    ip: str = Field(..., description="IP-Adresse des Tasmota-Geräts.")

    @validator("ip")
    def validate_ip(cls, ip):
        """
        Validiert die IP-Adresse im IPv4-Format.
        """
        ip_regex = re.compile(
            r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
        )
        if not ip_regex.match(ip):
            raise ValueError("Ungültige IP-Adresse. Erlaubt ist nur das IPv4-Format.")
        return ip

    def __str__(self):
        """
        Gibt die Authentifizierungsinformationen in einer sicheren, gekürzten Form aus.
        """
        return f"WebAuth(user={self.user}, ip={self.ip})"

def get_command_class(command: str) -> GeneralCommand:
    subclasses = GeneralCommand.__subclasses__()
    for subclass in subclasses:
        command_field = subclass.__fields__.get('command')
        if command_field and command_field.type_.__args__[0].lower() == command.lower():
            return subclass
    raise ValueError(f"Kein Befehl gefunden, der mit '{command}' übereinstimmt.")


class TasmotaCommand:
    def __init__(self, command, user=None, pw=None, ip=None, auth=None):
        if not isinstance(command, GeneralCommand):
            raise TypeError("command must be an instance of a subclass of GeneralCommand")
        if auth!=None and not isinstance(auth, WebAuth):
            raise TypeError("auth must be an instance of a subclass of WebAuth")
      
        self.command = command
        
        if not auth:
            if not all([user, pw, ip]):
                raise ValueError("When 'auth' is None, 'user', 'pw', and 'ip' must be provided.")
            self.user = user
            self.pw = pw
            self.ip = ip
        else:
            self.user = auth.user
            self.pw = auth.pw
            self.ip = auth.ip
            
        self.response = None

    def execute(self):
        # URL encode the command
        encoded_command = urllib.parse.quote(str(self.command))
        url = f'http://{self.ip}/cm?user={self.user}&password={self.pw}&cmnd={encoded_command}'
        
        try:
            response = requests.get(url)
            # Check if the status code indicates success (2xx range)
            if not (200 <= response.status_code < 300):
                raise Exception(f"Request failed with status code {response.status_code}")

            self.response = response.json()
            return self.response
        except requests.exceptions.RequestException as e:
            print(f"Error executing command '{self.command}': {e}")
            return None

if __name__ == '__main__':
    pass
    self = TasmotaConfigParser('../config.yml')
