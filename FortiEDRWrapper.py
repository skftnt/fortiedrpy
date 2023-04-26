#!/usr/bin/env Python
__version__ = "0.3.0"

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
        
    def get_event_exceptions(self, params):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/exceptions/get-event-exceptions")
        if self.organization:
            params["organization"] = self.organization
        try:
            response = self.session.get(url, params=params, verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                response.raise_for_status()
        else:
            return response.json()

    def get_event_exceptions(self, params):
    url = urllib.parse.urljoin(self.base_url, "/management-rest/exceptions/get-event-exceptions")
    if self.organization:
        params["organization"] = self.organization
    try:
        response = self.session.get(url, params=params, verify=self.verify_ssl)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 400:
            raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
        elif response.status_code == 500:
            raise ValueError("Internal Server Error: An unexpected error occurred.")
        else:
            response.raise_for_status()
    else:
        return response.json()

    
    def delete_exception(self, params):
    url = urllib.parse.urljoin(self.base_url, "/management-rest/exceptions/delete")
    if self.organization:
        params["organization"] = self.organization
    try:
        response = self.session.delete(url, params=params, verify=self.verify_ssl)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 400:
            raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
        elif response.status_code == 500:
            raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
        else:
            response.raise_for_status()
    else:
        return response.json()

    
    def list_exceptions(self, params):        
    url = urllib.parse.urljoin(self.base_url, "/management-rest/exceptions/list-exceptions")    
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
    
    
   def create_or_edit_exception(self, params, jsonData, confirm_edit=False):
    url = urllib.parse.urljoin(self.base_url, "/management-rest/exceptions/create-or-edit-exception")
    
    if self.organization:
        params["organization"] = self.organization
        
    try:
        response = self.session.post(url, headers={"Content-Type": "application/json"}, params=params, json=jsonData, verify=self.verify_ssl)
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
    
        def list_products(self, params):
        if self.organization:
            params["organization"] = self.organization

        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/list-products")

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

    def set_policy_mode(self, policy_names, mode, organization=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/set-policy-mode")
        params = {
            "policyNames": ",".join(policy_names),
            "mode": mode,
        }
        if organization:
            params["organization"] = organization

        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def assign_collector_group(self, collector_groups, policy_name, organization=None, force_assign=False):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/assign-collector-group")
        params = {
            "collectorGroups": ",".join(collector_groups),
            "policyName": policy_name,
            "forceAssign": force_assign,
        }
        if organization:
            params["organization"] = organization

        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def set_policy_permission(self, vendors, products, versions, policies, decision, signed=None, apply_nested=None,
                              organization=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/set-policy-permission")
        params = {
            "vendors": ",".join(vendors),
            "products": ",".join(products),
            "versions": ",".join(versions),
            "policies": ",".join(policies),
            "decision": decision
        }
        if signed is not None:
            params["signed"] = signed
        if apply_nested is not None:
            params["applyNested"] = apply_nested
        if organization:
            params["organization"] = organization

        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def clone_policy(self, source_policy_name, new_policy_name, organization=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/clone-policy")
        params = {
            "sourcePolicyName": source_policy_name,
            "newPolicyName": new_policy_name
        }
        if organization:
            params["organization"] = organization

        try:
            response = self.session.post(url, headers={"Content-Type": "application/json"}, params=params,
                                         verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def list_policies(self, organization=None, policies=None, rules=None, sources=None, state=None, decisions=None,
                      pageNumber=None, strictMode=False, itemsPerPage=100, sorting=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/list-policies")
        params = {
            "strictMode": strictMode,
            "itemsPerPage": itemsPerPage
        }
        if organization:
            params["organization"] = organization
        if policies:
            params["policies"] = ','.join(policies)
        if rules:
            params["rules"] = ','.join(rules)
        if sources:
            params["sources"] = ','.join(sources)
        if state:
            params["state"] = state
        if decisions:
            params["decisions"] = ','.join(decisions)
        if pageNumber:
            params["pageNumber"] = pageNumber
        if sorting:
            params["sorting"] = sorting

        try:
            response = self.session.get(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def resolve_applications(self, organization=None, vendors=None, products=None, versions=None,
                             signed=None, applyNested=None, comment=None, resolve=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/resolve-applications")
        params = {}
        if organization:
            params["organization"] = organization
        if vendors:
            params["vendors"] = ','.join(vendors)
        if products:
            params["products"] = ','.join(products)
        if versions:
            params["versions"] = ','.join(versions)
        if signed is not None:
            params["signed"] = signed
        if applyNested is not None:
            params["applyNested"] = applyNested
        if comment:
            params["comment"] = comment
        if resolve is not None:
            params["resolve"] = resolve

        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()

    def set_policy_rule_state(self, policyName, ruleName, state, organization=None):
        url = urllib.parse.urljoin(self.base_url, "/management-rest/comm-control/set-policy-rule-state")
        params = {
            "policyName": policyName,
            "ruleName": ruleName,
            "state": state
        }
        if organization:
            params["organization"] = organization

        try:
            response = self.session.put(url, headers={"Content-Type": "application/json"}, params=params,
                                        verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                raise ValueError("Bad Request: The given parameters do not match the expected format or values range.")
            elif response.status_code == 500:
                raise ValueError("Internal Server Error: An unexpected error occurred. Contact Fortinet support.")
            else:
                raise e
        else:
            return response.json()
