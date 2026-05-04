import requests


class NewtonAuthHTTPClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, auth_timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_timeout = auth_timeout
        self._session = requests.Session()
        self._session.auth = (self.client_id, self.client_secret)

    def auth_check(self, uid: str, platform_token: str) -> dict:
        response = self._session.post(
            "{}/platform-auth/auth/check/".format(self.base_url),
            json={"uid": uid, "platform_token": platform_token},
            timeout=self.auth_timeout,
        )
        if response.status_code == 401:
            return {
                "authenticated": False,
                "authorized": False,
                "uid": uid,
                "first_name": "",
                "last_name": "",
                "email": "",
                "client_cache_ttl_seconds": 60,
                "session_ttl_seconds": 86400,
                "should_clear_session": True,
            }
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._session.close()
