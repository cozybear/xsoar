register_module_line('Palo Alto Networks Enterprise DLP', 'start', __line__())
demisto.debug('pack name = Enterprise DLP by Palo Alto Networks, pack version = 2.0.15')

import urllib3
import urllib.parse
from enum import Enum
from string import Template
import bz2
import base64
import math


# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBAL PARAMETERS'''
BASE_URL = 'https://api.dlp.paloaltonetworks.com/v1/'
PAN_AUTH_URL = 'https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token'
INCIDENTS_URL = 'public/incident-notifications'
#S3_URL = 'api/evidence/download/:{reportId}'
S3_URL = 'api/evidence/download/'
CREDENTIAL = 'credential'
IDENTIFIER = 'identifier'
PASSWORD = 'password'
MAX_ATTEMPTS = 3


class Client(BaseClient):

    def __init__(self, url, credentials, insecure, proxy):
        super().__init__(base_url=url, headers=None, verify=not insecure, proxy=proxy)
        self.credentials = credentials
        credential_name = credentials[CREDENTIAL]
        if not credential_name:
            self.access_token = credentials[IDENTIFIER]
            self.refresh_token = credentials[PASSWORD]
        else:
            self.access_token = ''
            self._refresh_token_with_client_credentials()




    def _refresh_token(self):
        """Refreshes Access Token"""
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        params = {
            "refresh_token": self.refresh_token
        }
        print_debug_msg(f'Calling endpoint {self._base_url}{REFRESH_TOKEN_URL}')
        try:
            r = self._http_request(
                method='POST',
                headers=headers,
                url_suffix=REFRESH_TOKEN_URL,
                json_data=params,
                ok_codes=[200, 201, 204]
            )
            new_token = r.get('access_token')
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise

    def _refresh_token_with_client_credentials(self):
        client_id = self.credentials[IDENTIFIER]
        client_secret = self.credentials[PASSWORD]
        credentials = f'{client_id}:{client_secret}'
        auth_header = f'Basic {b64_encode(credentials)}'
        headers = {
            'Authorization': auth_header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = 'grant_type=client_credentials'
        try:
            r = self._http_request(
                full_url=PAN_AUTH_URL,
                method='POST',
                headers=headers,
                data=payload,
                ok_codes=[200, 201, 204]
            )
            new_token = r.get('access_token')
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise


    def _handle_403_errors(self, res):
        """
        Handles 403 exception on get-dlp-report and tries to refresh token
        Args:
            res: Response of DLP API call
        """
        if res.status_code != 403:
            return
        try:
            print_debug_msg("Got 403, attempting to refresh access token")
            if self.credentials[CREDENTIAL]:
                print_debug_msg("Requesting access token with client id/client secret")
                self._refresh_token_with_client_credentials()
            else:
                print_debug_msg("Requesting new access token with old access token/refresh token")
                self._refresh_token()
        except Exception:
            pass


    def _get_dlp_api_call(self, url_suffix: str):
        """
        Makes a HTTPS Get call on the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
        """
        count = 0
        print_debug_msg(f'Calling GET method on {self._base_url}{url_suffix}')
        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method='GET',
                headers={'Authorization': "Bearer " + self.access_token},
                url_suffix=url_suffix,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_403_errors,
                resp_type='',
                return_empty_response=True
            )
            if res.status_code != 403:
                break
            count += 1

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError
            except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                result_json = {}

        return result_json, res.status_code


    def pan_dlp_get_s3_url(self, report_id, service_name, original_file_name, user_id="Test"):
        url = S3_URL
        params = {
                    "originalFileName": original_file_name,
                    "userId": user_id
                    }

        query_string = urllib.parse.urlencode(params)
        #s3_url = f"{S3_URL}:{report_id}?{query_string}"
        s3_url = f"{S3_URL}{report_id}"
        full_url = f"{BASE_URL}{s3_url}"

        #full_url = f"https://api.dlp.paloaltonetworks.com/v1/api/evidence/download/3409426969"
        res = self._http_request(
            method='GET',
            full_url=full_url,
            headers={'Authorization': "Bearer " + self.access_token,
                    'Accept': 'application/json',
                    "service-name": service_name
            },
            params=params
            #resp_type='',
            # return_empty_response=True
            )
        return res




    def get_dlp_incidents(self, regions: str, start_time: int = None, end_time: int = None) -> tuple:
        url = INCIDENTS_URL
        params = {}
        if regions:
            params['regions'] = regions
        if start_time:
            params['start_timestamp'] = str(start_time)
        if end_time:
            params['end_timestamp'] = str(end_time)
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
        resp, status_code = self._get_dlp_api_call(url)
        return resp, status_code


def pan_dlp_get_s3_url_command(client: Client, args: dict):
    report_id = args.get('report_id')
    service_name = args.get('service_name')
    original_file_name = args.get('original_file_name')
    user_id = args.get('user_id')
    result = client.pan_dlp_get_s3_url(report_id, service_name, original_file_name, user_id)
    #return result
    return CommandResults(outputs_prefix="S3URL", outputs=result)


def test(client: Client, params: dict):
    """ Test Function to test validity of access and refresh tokens"""
    dlp_regions = params.get("dlp_regions", "")
    report_json, status_code = client.get_dlp_incidents(regions=dlp_regions)
    if status_code in [200, 204]:
        return_results("ok")
    else:
        message = f"Integration test failed: Unexpected status ({status_code}) - "
        if "error" in report_json:
            message += f"Error message: \"{report_json.get('error')}\""
        else:
            message += "Could not determine the error reason. Make sure the DLP Regions parameter is configured correctly."
        raise DemistoException(message)


def print_debug_msg(msg: str):
    """
    Prints a message to debug with PAN-DLP-Msg prefix.
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f'PAN-DLP-Msg - {msg}')



def main():

    try:
        demisto.info(f'Command is {demisto.command()}')
        params = demisto.params()
        print_debug_msg(f'Received parameters: {",".join(params.keys())}.')
        credentials = params.get('credentials')

        client = Client(BASE_URL, credentials, params.get('insecure'), params.get('proxy'))
        args = demisto.args()

        if demisto.command() == 'pan-dlp-get-s3-url':
            result = pan_dlp_get_s3_url_command(client, args)
            return_results(result)
        elif demisto.command() == "test-module":
            test(client, params)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()

register_module_line('Palo Alto Networks Enterprise DLP', 'end', __line__())

