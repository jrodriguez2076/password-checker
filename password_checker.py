import requests
import hashlib
import os
from dotenv import load_dotenv

import pdb

load_dotenv()

"""Singleton metaclass
"""
class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

"""Password Checker class

Definition of the password checker.
This class uses the open endpoints for the HIBP API. Other Endpoints can
be implemented if using an API Key.

"""
class pasword_checker(metaclass=Singleton):


    def __init__(self, registered=False):
        """
        Initialization of class parameters. RANGE_URL and MAIN_URL need to be declared
        as environment variables. 

        Parameters:
        registered (bool): specifies if the password checker can use the API endoints
        that require an API key
        """

        self.range_url = os.getenv('RANGE_URL')
        self.main_url = os.getenv('MAIN_URL')
        self.registered = registered



    def password_range_breach(self, query_char):
        """
        Check for a password using the K-anonimity principle followed by the HIBP API

        Parameters:
        query_char (string): first 5 characters of SHA1 encoding of the password submitted

        Returns:
        response: list of passwords starting with 'query_char' that have been breached 
        """

        url = self.range_url + query_char
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(f'Error Fetching data: {res.status_code}')
        return res

    def check_password_breach(self, password):
        """
        high-level method for checking how many times has a password been breached

        Parameters:
        Password (string): string to test for breach

        Returns:
        int: number of times that 'password' has been used
        """

        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        head, tail = sha1password[:5], sha1password[5:]
        response = self.password_range_breach(head)
        return self.count_pw_leaks(response, tail)


    def count_pw_leaks(self, hash_list, hash):
        """
        iterates through a list of hashed passwords and matches a specified hash
        tail.

        Parameters:
        hash_list (response Object): List of hashed passwords.
        hash (string): tail of the password submitted and encoded in SHA1

        Returns:
        int: count value for the password.
        """

        hash_list = (line.split(':') for line in hash_list.text.splitlines())
        for h, count in hash_list:
            if h == hash:
                return count
        return 0

    def check_breached_sites(self, site_domain=''):
        """
        Search for all sites that have been breached, or for a specific site,
        using the site domain

        Parameters:
        site_domain (string): domain name to use as query parameter. Optional

        Returns:
        JSON: Matches found for domain specified, If no domain is specified, returns
        all breached sites
        """

        url = self.main_url + 'breaches'
        res = requests.get(url, params={'domain': site_domain})
        if res.status_code != 200:
            raise RuntimeError(f'Error Fetching data: {res.status_code}')
        data = res.json()[0] if site_domain != '' and len(res.json()) > 0 else res.json()
        return data

    def get_breach_name(self, site_domain=''):
        """
        Search for a specific site breach name, using the specified domain.

        Parameters:
        site_domain (string): domain name to use as query parameter. Optional

        Returns:
        string: returns the name of the breach. if it is not found, return None
        """

        site_data = self.check_breached_sites(site_domain)
        if len(site_data) == 1:
            return site_data['name']
        else:
            return None
    
    def check_breach_by_name(self, name=None, site_domain=None):
        """
        Search for a specific site breach by name. If no name is provided, use
        site domain to search for it, then fetch the corresponding breach

        Parameters:
        name (string): breach name.
        site_domain (string): domain name to use as query parameter. Optional

        Returns:
        string: returns the name of the breach. if it is not found, return None
        """

        try:
            name_param = ''
            if name:
                name_param = name
            elif site_domain:
                name_param = self.get_breach_name(site_domain)
            else:
                raise RuntimeError(f'Error fetching breach by name: You must specify a name or a domain name')
            url = self.main_url + 'breach/' + name_param
            res = requests.get(url)
            return res
        except Exception as err:
            raise RuntimeError(f'Error fetching breach by name. {err}')