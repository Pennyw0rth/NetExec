import base64
import datetime
import hashlib
import hmac
import json
import time
import urllib

import requests

class ApiException(Exception):
    """Exception subclass used to indicate a problem while communicating with the API."""

    response = None
    """Instance of requests.models.Response containing the response that causes a problem."""

    def __init__(self, message, response=None):
        super().__init__(message)
        self.response = response


class BloodHoundAPI:
    """Api class for interacting with the BloodHound API server."""

    _url = None
    """Base URL of the API server."""
    _token_id = None
    """ID of the API token used for authentication."""
    _token_key = None
    """Value of the API token used for authentication."""
    _bearer = None
    """Bearer token as an alternative to the API token for authentication."""
    _logger = None
    """Logger object from netexec"""


    def __init__(self, url, token_id=None, token_key=None, bearer=None, logger=None):
        """Create an instance of the Api class and set URL and authentication data.
        Either token_id + token_key or a bearer token needs to be set for authentication
        as long as the Api is not just used for initial login.
        """
        self._url = url
        self._token_id = token_id
        self._token_key = token_key
        self._bearer = bearer
        self._logger = logger


    def _send(self, method, endpoint, data=None, content_type="application/json"):
        """Send a request to the API and return the JSON data from the response."""
        if not self._url:
            raise ApiException("Invalid API URL configured, run the auth subcommand first.")

        endpoint_url = urllib.parse.urljoin(self._url, endpoint)
        headers = {
            "User-Agent": "bhcli-netexec",
        }

        if data is not None:
            if isinstance(data, (dict, list)):
                data = json.dumps(data).encode()
            headers["Content-Type"] = content_type

        if self._token_id is not None:
            # compute the authentication MAC according to the BloodHound docs
            digester = hmac.new(self._token_key.encode(), None, hashlib.sha256)
            digester.update(f"{method}{endpoint}".encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
            digester.update(datetime_formatted[:13].encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            if data is not None:
                digester.update(data)
            headers["Authorization"] = f"bhesignature {self._token_id}"
            headers["RequestDate"] = datetime_formatted
            headers["Signature"] = base64.b64encode(digester.digest())
        elif self._bearer is not None:
            # use Bearer authentication as an alternative
            headers["Authorization"] = f"Bearer {self._bearer}"

        self._logger.debug("Sending %s request to API endpoint %s", method, endpoint)
        result = requests.request(method=method, url=endpoint_url, headers=headers, data=data, timeout=(3.1, 60))
        self._logger.debug("Received response with code %d:", result.status_code)
        self._logger.debug("%s", result.text)

        if not result.ok:
            if result.status_code == 401:
                raise ApiException("Authentication failure, try to obtain an API token with the auth subcommand first.", result)
            if result.status_code == 429:
                rate_limit_duration = int(result.headers["X-Rate-Limit-Duration"])
                self._logger.info("Hit request rate limiting. Waiting for %d seconds, then trying again...", rate_limit_duration)
                time.sleep(rate_limit_duration)
                return self._send(method, endpoint, data, content_type)
            raise ApiException("Received unexpected response from server. Run 'bhcli --debug ...' for more information.", result)

        if result.content:
            return result.json()["data"]
        return {}

    def search(self, name, kind=None):
        """Search for a node by name, optionally restricted to a specific kind."""
        endpoint = f"/api/v2/search?q={urllib.parse.quote_plus(name)}"
        if kind is not None:
            endpoint += f"&type={urllib.parse.quote_plus(kind)}"
        return self._send("GET", endpoint)

    def get_member_asset_groups(self, asset_group_id, objectID=None):
        """Get asset groups."""
        endpoint = f"/api/v2/asset-groups/{asset_group_id}/members"
        if objectID is not None:
            endpoint += f"?object_id=eq:{objectID}"
        return self._send("GET", endpoint)

    def add_to_asset_group(self, asset_group_id, sids):
        """Add one or more objects identified by their sid to an asset group."""
        endpoint = f"/api/v2/asset-groups/{asset_group_id}/selectors"
        if isinstance(sids, str):
            sids = [sids]
        data = [
            {
                "action": "add",
                "selector_name": sid,
                "sid": sid,
            }
            for sid in sids
        ]
        return self._send("PUT", endpoint, data)

    def domains(self, collected=None):
        """Return available domains."""
        endpoint = "/api/v2/available-domains"
        if collected is not None:
            endpoint += f"?collected=eq:{str(collected).lower()}"
        return self._send("GET", endpoint)