#!/usr/bin/env Python
__version__ = "0.1.0"

import base64
import requests
import urllib.parse

class FortiEDRWrapper:
    def __init__(self, base_url, username, password, organization=None, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.organization = organization
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.authenticate()

    def authenticate(self):
        auth_data = f"{self.organization}\\{self.username}:{self.password}" if self.organization else f"{self.username}:{self.password}"
        encoded_auth_data = base64.b64encode(auth_data.encode("utf-8")).decode("utf-8")
        self.session.headers.update({"Authorization": f"Basic {encoded_auth_data}"})
        response = self.session.post(urllib.parse.urljoin(self.base_url, "/login"), verify=self.verify_ssl)
        response.raise_for_status()

    def list_events(self, params):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events/list-events")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.get(url, headers={"Content-Type": "application/json"}, params=params, verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred.")
            else:
                raise e
        else:
            return response.json()

    def list_raw_data_items(self, params):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events/list-raw-data-items")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.get(url, headers={"Content-Type": "application/json"}, params=params, verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred.")
            else:
                raise e
        else:
            return response.json()

    def update_events(self, params, data):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params, json=data,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. ")
            else:
                raise e
        else:
            return response.json()

    def delete_events(self, params):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.delete(url, headers={"Content-Type": "application/json"}, params=params,
                                           verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred.")
            else:
                raise e
        else:
            return response.json()

    def create_exception(self, url_params, json_data):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events/create-exception")
        if self.organization:
            url_params["organization"] = self.organization
        try:
            response = self.session.post(url, params=url_params, json=json_data, verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred.")
            else:
                raise e
        else:
            return response.json()

    def count_events(self, params):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/events/count-events")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.get(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred.")
            else:
                raise e
        else:
            return response.json()

