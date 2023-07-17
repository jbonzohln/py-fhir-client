import json
import uuid
from datetime import datetime, timedelta

import requests as requests

import time
import jwt
import cryptography

APPLICATION_JSON_FHIR = "application/json+fhir"


class FhirClient:
    def __init__(self, base_url: str = None, token: str = None, auth_type: str = None):
        self.base_url = base_url.removesuffix("/")
        self.token = token
        self.auth_type = auth_type

    def headers(self):
        if self.token is not None and self.auth_type is not None:
            return {
                "Authorization": f"{self.auth_type} {self.token}",
                "Accept": APPLICATION_JSON_FHIR,
                "Content-Type": APPLICATION_JSON_FHIR
            }
        else:
            return {
                "Accept": APPLICATION_JSON_FHIR,
                "Content-Type": APPLICATION_JSON_FHIR
            }

    def get_smart_configuration(self):
        response = requests.get(url=f"{self.base_url}/.well-known/smart-configuration")
        response.raise_for_status()
        return response.json()

    def oauth(self, client_id: str = '', key_id: str = '', key: str = '', jku: str = None, algorithm: str = 'RS384'):
        smart_config = self.get_smart_configuration()
        token_endpoint = smart_config['token_endpoint']

        encoded_jwt = jwt.encode(
            payload={
                "iss": client_id,
                "sub": client_id,
                "aud": token_endpoint,
                "exp": datetime.utcnow() + timedelta(hours=1),
                "jti": str(uuid.uuid4()),
                "jku": jku
            },
            key=key,
            algorithm=algorithm,
            headers={
                "kid": key_id
            })

        response = requests.post(token_endpoint, params={
            'grant_type': 'client_credentials',  # fixed value
            # 'scope': 'system/*.rc',
            'client_assertion': encoded_jwt,  # signed jwt
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'  # fixed value
        }, headers={
            'Accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded'
        })
        return response.json()

    def get_resource(self, resource_type: str, resource_id: str) -> dict:
        response = requests.get(url=f"{self.base_url}/{resource_type}/{resource_id}", headers=self.headers())
        response.raise_for_status()
        return response.json()

    def operation_on_resource(self, resource_type: str, resource_id: str, operation: str, mutation_body: dict) -> dict:
        data = json.dumps(mutation_body)
        response = requests.post(url=f"{self.base_url}/{resource_type}/{resource_id}/{operation}",
                                 headers=self.headers(),
                                 data=data)
        response.raise_for_status()
        return response.json()

    def operation_on_resource_type(self, resource_type: str, operation: str, mutation_body: dict) -> dict:
        data = json.dumps(mutation_body)
        response = requests.post(url=f"{self.base_url}/{resource_type}/{operation}",
                                 headers=self.headers(),
                                 data=data)
        response.raise_for_status()
        return response.json()

    def get_group(self, group_id: str) -> dict:
        return self.get_resource("Group", group_id)

    def get_patient(self, patient_id: str) -> dict:
        return self.get_resource("Patient", patient_id)

    def member_remove(self, group_id: str, patient_id: str) -> dict:
        return self.mutate_group(group_id, patient_id, "$member-remove")

    def member_add(self, group_id: str, patient_id: str):
        return self.mutate_group(group_id, patient_id, "$member-add")

    def mutate_group(self, group_id: str, patient_id: str, operation: str) -> dict:
        return self.operation_on_resource("Group", group_id, operation, {
            "resourceType": "Parameters",
            "id": f"{time.time_ns()}",
            "parameter": [
                {
                    "name": "patientReference",
                    "valueReference": {
                        "reference": f"{patient_id}",
                        "type": "Patient"
                    }
                }
            ]
        })

    def patient_match(self, search_criteria: dict, count: int = 3, certain_matches: bool = False) -> dict:
        return self.operation_on_resource_type("Patient", "$match", {
            "resourceType": "Parameters",
            "id": f"{time.time_ns()}",
            "parameter": [
                {
                    "name": "resource",
                    "resource": {
                        "resourceType": "Patient",
                        **search_criteria
                    }
                },
                {
                    "name": "count",
                    "valueInteger": count
                },
                {
                    "name": "onlyCertainMatches",
                    "valueBoolean": certain_matches
                }
            ]
        })
