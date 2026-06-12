import requests
import config
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
       
class UserFetcher:
    def __init__(self, base_url=config.BASE_URL, identity=config.encrypted_user, secret=config.encrypted_pass):
        """
        Initializes the UserFetcher with a base URL and credentials.
        identity and secret can be JSON objects (dict).
        """
        if not base_url:
            raise ValueError("Base URL cannot be empty.")
        if not isinstance(base_url, str):
            raise TypeError("Base URL must be a string.")

        # identity and secret can be either string or dict
        if isinstance(identity, dict):
            self.identity = identity
        else:
            raise TypeError("Identity must be a string or dict.")

        if isinstance(secret, dict):
            self.secret = secret
        else:
            raise TypeError("Secret must be a string or dict.")

        self.base_url = base_url

        logging.info(f"UserFetcher initialized with base_url: {self.base_url}")
        logging.info(f"Identity: {self.identity}")
        logging.info(f"Secret: {self.secret}")
    
    def fetch_auth_token(self):
        """
        Fetches the authentication token from the API.
        :return: A dict with 'access_token' and 'refresh_token' if successful, None otherwise.
        """
        url = f"{self.base_url}/users/tokens/issue"
        try:
            headers = {'Content-Type': 'application/json'}
            
            payload = json.dumps({
                "identity": self.identity,
                "secret": self.secret,
            })
            logging.info(f"Requesting auth token from {url} with payload: {payload}")
            
            response = requests.request("POST", url, headers=headers, data=payload)

            response.raise_for_status()
            token_data = response.json()

            data = token_data.get("data", {})
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")

            if access_token and refresh_token:
                logging.info("Authentication tokens fetched successfully.")
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            else:
                logging.error("Missing access or refresh token in the response.")
                return None

        except requests.RequestException as e:
            logging.error(f"Error fetching auth token: {e}")
            return None
        except ValueError as e:
            logging.error(f"Error parsing token response: {e}")
            return None
    
           
    def fetch_domain_id(self):
        """
        Fetches the domain ID from the API.
        :return: The domain ID if successful, None otherwise.
        """
        tokens = self.fetch_auth_token()
        if not tokens or not tokens.get("access_token"):
            logging.error("Failed to fetch users: no valid auth token.")
            return None
        
        url = f"{self.base_url}/domains"
        try:
            headers = {
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "application/json"
                }
            payload = {}
            logging.info(f"Requesting domain ID from {url} with payload: {payload}")
            
            response = requests.request("GET", url, headers=headers, data=payload)

            response.raise_for_status()
            domain_data = response.json()

            domains = domain_data.get("domains")
            if domains and isinstance(domains, list) and len(domains) > 0:
                domain_id = domains[0].get("id")
                logging.info(f"Domain ID fetched successfully: {domain_id}")
                return domain_id
            else:
                logging.warning("No domains found in the response.")
                return None

        except requests.RequestException as e:
            logging.error(f"Error fetching domain ID: {e}")
            return None
        
    def fetch_auth_token_with_domain_id(self):
        """
        Fetches the authentication token with domain ID from the API.
        :return: A dict with 'access_token' and 'refresh_token' if successful, None otherwise.
        """
        domain_id = self.fetch_domain_id()
        if not domain_id:
            logging.error("Failed to fetch auth token: no valid domain ID.")
            return None

        url = f"{self.base_url}/users/tokens/issue"
        try:
            headers = {'Content-Type': 'application/json'}
            
            payload = json.dumps({
                "identity": self.identity,
                "secret": self.secret,
                "domain_id": domain_id
            })
            logging.info(f"Requesting auth token with domain ID from {url} with payload: {payload}")
            
            response = requests.request("POST", url, headers=headers, data=payload)

            response.raise_for_status()
            token_data = response.json()

            data = token_data.get("data", {})
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")

            if access_token and refresh_token:
                logging.info("Authentication tokens with domain ID fetched successfully.")
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            else:
                logging.error("Missing access or refresh token in the response.")
                return None

        except requests.RequestException as e:
            logging.error(f"Error fetching auth token with domain ID: {e}")
            return None
        except ValueError as e:
            logging.error(f"Error parsing token response: {e}")
            return None

    def fetch_all_users(self):
        """
        Fetches all users from the API.
        :return: A list of users if the request is successful, None otherwise.
        """
        tokens = self.fetch_auth_token_with_domain_id()
        if not tokens or not tokens.get("access_token"):
            logging.error("Failed to fetch users: no valid auth token.")
            return None

        url = f"{self.base_url}/users"
        try:
            
            payload = {}
            headers = {
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "application/json"
            }
            params = {
                "limit": 100,
                "offset": 0,
                "status": "enabled"
            }

            response = requests.request("GET", url, headers=headers, data=payload, params=params)
            
            response.raise_for_status()
            logging.info("Fetched user list successfully.")
            logging.info(f"User list response: {response.json()}")
            return response.json()
            
        except requests.RequestException as e:
            logging.error(f"Error fetching users: {e}")
            return None
        except ValueError as e:
            logging.error(f"Error parsing user list response: {e}")
            return None

    def fetch_all_users_vault(self):
        """
        Fetches all users from the API (handles pagination automatically).
        :return: A list of all users if successful, None otherwise.
        """
        tokens = self.fetch_auth_token_with_domain_id()

    # Handle case where tokens is a list instead of a dict
        if isinstance(tokens, list) and len(tokens) > 0:
            tokens = tokens[0]
            
        if not tokens or not tokens.get("access_token"):
            logging.error("Failed to fetch users: no valid auth token.")
            return None

        url = f"{self.base_url}/users"
        headers = {
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/json"
        }

        all_users = []
        limit = 100
        offset = 0

        try:
            while True:
                params = {
                    "limit": limit,
                    "offset": offset,
                    "status": "enabled"
                }

                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()

            # Assuming API response structure: {"users": [...], "total": 123}
                users = data.get("users", [])
                total = data.get("total", 0)

                all_users.extend(users)

                logging.info(f"Fetched {len(users)} users (offset={offset}).")

            # Stop if fewer than limit were returned → no more pages
                if len(all_users) >= total or len(users) == 0:
                    break

                offset += limit

            logging.info(f"Total users fetched: {len(all_users)}")
            return {"users": all_users}

        except requests.RequestException as e:
            logging.error(f"Error fetching users: {e}")
            return None
        except ValueError as e:
            logging.error(f"Error parsing user list response: {e}")
            return None
