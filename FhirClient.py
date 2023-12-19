import json
import uuid
from datetime import datetime, timedelta, timezone
import time
import jwt
from requests import Response, Session
from requests_toolbelt.downloadutils import stream
from logging import getLogger

APPLICATION_JSON_FHIR = 'application/json+fhir'


class FhirClient:
    def __init__(self, base_url: str = None, token: str = None, auth_type: str = None):
        self.logging = getLogger('FhirClient')
        self.base_url = base_url.removesuffix('/')
        self.token = token
        self.token_expires_at: datetime = datetime.now()
        self.refresh_token = lambda: ''
        self.auth_type = auth_type
        self.session = Session()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.session.close()

    def __get_token(self):
        if self.token_expires_at is not None and datetime.now() > self.token_expires_at:
            self.refresh_token()
        return self.token

    def __headers(self) -> dict:
        if self.__get_token() is not None and self.auth_type is not None:
            return {
                'Authorization': f'{self.auth_type} {self.__get_token()}',
                'Accept': APPLICATION_JSON_FHIR,
                'Content-Type': APPLICATION_JSON_FHIR
            }
        else:
            return {
                'Accept': APPLICATION_JSON_FHIR,
                'Content-Type': APPLICATION_JSON_FHIR
            }

    def __async_headers(self) -> dict:
        return {
            **self.__headers(),
            'Prefer': 'respond-async'
        }

    def __operation(self,
                    url: str,
                    query_params: dict[str, str] = None,
                    data: str = None) -> dict:
        if data is None:
            op = self.session.get
        else:
            op = self.session.post

        with op(url=url, headers=self.__headers(), params=query_params, data=data) as response:
            response.raise_for_status()
            if response.content:
                return response.json()
            else:
                return {}

    def __operation_on_resource(self,
                                resource_type: str,
                                resource_id: str,
                                operation: str,
                                query_params: dict[str, str] = None,
                                body: dict = None) -> dict:
        if body is None:
            data = None
        else:
            data = json.dumps(body)

        return self.__operation(url=f"{self.base_url}/{resource_type}/{resource_id}/{operation}",
                                query_params=query_params,
                                data=data)

    def __operation_on_resource_type(self,
                                     resource_type: str,
                                     operation: str = None,
                                     query_params: dict[str, str] = None,
                                     body: dict = None) -> dict:
        if body is None:
            data = None
        else:
            data = json.dumps(body)

        if operation is None:
            return self.__operation(url=f'{self.base_url}/{resource_type}',
                                    query_params=query_params,
                                    data=data)
        else:
            return self.__operation(url=f'{self.base_url}/{resource_type}/{operation}',
                                    query_params=query_params,
                                    data=data)

    def __async_operation(self,
                          url: str,
                          query_params: dict[str, str] = None,
                          data: str = None):
        if data is None:
            op = self.session.get
        else:
            op = self.session.post

        with op(url=url, params=query_params, headers=self.__async_headers(), data=data) as response:
            response.raise_for_status()
            return response

    def __async_operation_on_resource(self,
                                      resource_type: str,
                                      resource_id: str,
                                      operation: str,
                                      query_params: dict[str, str] = None,
                                      body: dict = None) -> Response:
        if body is None:
            data = None
        else:
            data = json.dumps(body)

        return self.__async_operation(url=f'{self.base_url}/{resource_type}/{resource_id}/{operation}',
                                      query_params=query_params,
                                      data=data)

    def __async_operation_on_resource_type(self,
                                           resource_type: str,
                                           operation: str,
                                           query_params: dict[str, str] = None,
                                           body: dict = None) -> Response:
        if body is None:
            data = None
        else:
            data = json.dumps(body)

        return self.__async_operation(url=f'{self.base_url}/{resource_type}/{operation}',
                                      query_params=query_params,
                                      data=data)

    def get_metadata(self):
        with self.session.get(url=f'{self.base_url}/metadata') as response:
            response.raise_for_status()
            return response.json()

    def get_smart_configuration(self):
        with self.session.get(url=f'{self.base_url}/.well-known/smart-configuration') as response:
            response.raise_for_status()
            return response.json()

    def oauth(self, client_id: str = '', key_id: str = '', key: str = '', jku: str = None, algorithm: str = 'RS384'):
        smart_config = self.get_smart_configuration()
        token_endpoint = smart_config['token_endpoint']

        encoded_jwt = jwt.encode(
            payload={
                'iss': client_id,
                'sub': client_id,
                'aud': token_endpoint,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'jti': str(uuid.uuid4()),
                'jku': jku
            },
            key=key,
            algorithm=algorithm,
            headers={
                'kid': key_id
            })

        with self.session.post(token_endpoint, params={
            'grant_type': 'client_credentials',  # fixed value
            # 'scope': 'system/*.rc',
            'client_assertion': encoded_jwt,  # signed jwt
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'  # fixed value
        }, headers={
            'Accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded'
        }) as response:
            return response.json()

    def read(self, resource_type: str, resource_id: str) -> dict:
        with self.session.get(url=f'{self.base_url}/{resource_type}/{resource_id}',
                              headers=self.__headers()) as response:
            response.raise_for_status()
            return response.json()

    def member_remove(self, group_id: str, patient_id: str) -> dict:
        return self.mutate_group(group_id, patient_id, '$member-remove')

    def member_add(self, group_id: str, patient_id: str):
        return self.mutate_group(group_id, patient_id, '$member-add')

    def mutate_group(self, group_id: str, patient_id: str, operation: str) -> dict:
        return self.__operation_on_resource(resource_type='Group',
                                            resource_id=group_id,
                                            operation=operation,
                                            body={
                                                'resourceType': 'Parameters',
                                                'id': f'{time.time_ns()}',
                                                'parameter': [
                                                    {
                                                        'name': 'patientReference',
                                                        'valueReference': {
                                                            'reference': f'{patient_id}',
                                                            'type': 'Patient'
                                                        }
                                                    }
                                                ]
                                            })

    def search(self, resource_type: str, query_params: dict):
        return self.__operation_on_resource_type(
            resource_type=resource_type,
            operation='_search',
            query_params=query_params
        )

    def validate(self, resource_type: str, resource, mode: str, profile: str = None):
        parameter = [
            {
                'name': 'resource',
                'resource': resource
            }
        ]

        if mode is not None and len(mode) > 0:
            parameter.append({
                'name': 'mode',
                'valueCode': mode
            })

        if profile is not None and len(profile) > 0:
            parameter.append({
                {
                    'name': 'profile',
                    'valueCode': profile
                }
            })

        return self.__operation_on_resource_type(
            resource_type=resource_type,
            operation='$validate',
            body={
                'resourceType': 'Parameters',
                'id': f'{time.time_ns()}',
                'parameter': parameter
            }
        )

    def create(self, resource_type: str, resource: dict):
        return self.__operation_on_resource_type(resource_type=resource_type, body=resource)

    def update(self, resource_type: str, resource: dict):
        pass

    def delete(self, resource_type: str, resource_id: str):
        with self.session.delete(url=f'{self.base_url}/{resource_type}/{resource_id}',
                                 headers=self.__headers()) as response:
            response.raise_for_status()
            if response.content:
                return response.json()
            else:
                return response.content

    def patient_match(self, search_criteria: dict, count: int = 3, certain_matches: bool = False) -> dict:
        return self.__operation_on_resource_type(
            resource_type='Patient',
            operation='$match',
            body={
                'resourceType': 'Parameters',
                'id': f'{time.time_ns()}',
                'parameter': [
                    {
                        'name': 'resource',
                        'resource': {
                            'resourceType': 'Patient',
                            **search_criteria
                        }
                    },
                    {
                        'name': 'count',
                        'valueInteger': count
                    },
                    {
                        'name': 'onlyCertainMatches',
                        'valueBoolean': certain_matches
                    }
                ]
            })

    def bulk_patient_export(self, since: datetime = None, types=None, default_polling_time: int = 120):
        if types is None:
            types = ['Patient']

        query_params: dict[str, str] = {
            '_type': ','.join(types)
        }

        if since is not None:
            query_params['_since'] = since.isoformat()

        response = self.__async_operation_on_resource_type(
            resource_type='Patient',
            operation='$export',
            query_params=query_params)

        if response.status_code == 202:
            content_location = response.headers['Content-Location']
            return self.poll(content_location, default_polling_time=default_polling_time)
        else:
            return response.json()

    def bulk_group_export(self, group_id: str, since: datetime = None, types=None):
        if types is None:
            types = ['Patient']

        query_params: dict[str, str] = {
            '_type': ','.join(types)
        }

        if since is not None:
            query_params['_since'] = since.isoformat()

        response = self.__async_operation_on_resource(
            resource_type='Group',
            resource_id=group_id,
            operation='$export',
            query_params=query_params)

        if response.status_code == 202:
            content_location = response.headers['Content-Location']
            return self.poll(content_location)
        else:
            return response.json()

    def bulk_patient_match(self, search_criteria: list, count: int = 3, certain_matches: bool = False,
                           default_polling_time: int = 120) -> dict:
        resource_params = [{
            'name': 'resource',
            'resource': {
                'resourceType': 'Patient',
                **sc
            }
        } for sc in search_criteria]

        # noinspection PyTypeChecker
        response = self.__async_operation_on_resource_type(resource_type='Patient',
                                                           operation='$bulk-match',
                                                           body={
                                                               'resourceType': 'Parameters',
                                                               'id': f'{time.time_ns()}',
                                                               'parameter': resource_params + [
                                                                   {'name': 'count', 'valueInteger': count},
                                                                   {'name': 'onlyCertainMatches',
                                                                    'valueBoolean': certain_matches}
                                                               ]
                                                           })

        if response.status_code == 202:
            content_location = response.headers['Content-Location']
            return self.poll(content_location, default_polling_time=default_polling_time)
        else:
            return response.json()

    def poll(self, poll_url: str, default_polling_time: int = 120):
        error_count = 0
        seconds = default_polling_time

        while True:
            with (self.session.get(url=poll_url, headers=self.__headers()) as response):
                if not response.ok:
                    self.logging.error(response.text)
                    if error_count < 3:
                        error_count += 1
                        seconds = default_polling_time
                    else:
                        raise response.raise_for_status()
                elif response.status_code == 200:
                    return response.json()
                elif 'Retry-After' in response.headers:
                    if 'X-Progress' in response.headers:
                        self.logging.info('X-Progress: {0}'.format(response.headers['X-Progress']))
                    retry_after = response.headers['Retry-After']
                    self.logging.info('Retry-After: {0}'.format(retry_after))
                    if retry_after.isnumeric():
                        seconds = int(retry_after)
                    else:
                        # Python is silly and doesn't parse the timezone, but the documentation says Retry-After
                        # should always be GMT
                        wait_until = datetime.strptime(retry_after, '%a, %d %b %Y %H:%M:%S %Z').replace(
                            tzinfo=timezone.utc)
                        seconds = (wait_until - datetime.now(timezone.utc)).seconds
                else:
                    self.logging.error(str(response))
                    raise Exception('Invalid poll response')
            seconds = min(seconds, 3600)
            self.logging.info('Sleeping for %d seconds', seconds)
            time.sleep(seconds)

    def save_output(self, output):
        """
        Saves the output from a bulk query to local files. The list of filenames is returned.
        """
        file_list = []

        for entry in output['output']:
            type_ = entry['type']
            url = entry['url']
            self.logging.info('type\t\t: %s', type_)
            self.logging.info('url\t\t: %s', url)

            with self.session.get(url=url, headers=self.__headers(), stream=True) as response:
                response.raise_for_status()

                file_name = url.split('/')[-1]
                with open(file_name, 'wb') as file:
                    file_name = stream.stream_response_to_file(response, path=file)
            self.logging.info('wrote to\t: %s', file_name)
            file_list.append(file_name)

        return file_list
