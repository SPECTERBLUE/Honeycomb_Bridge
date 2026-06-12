import logging
import grpc
import requests
import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from http_integration_fetcher import HttpIntegration  

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class HttpSender:
    def __init__(self, channel, auth_token):
        """
        Initialize HTTP Sender with ChirpStack gRPC connection.

        :param channel: gRPC channel for ChirpStack.
        :param auth_token: Authentication metadata for API calls.
        """
        self.http_integration = HttpIntegration(channel, auth_token)

    def _send_single_request(self, endpoint, headers, payload):
        """
        Helper method to send a single HTTP POST request.

        :param endpoint: The URL to send the request to.
        :param headers: Headers to include in the request.
        :param payload: The data to send in the HTTP POST request.
        """
        try:
            logging.info(f"Sending payload to {endpoint} with headers {headers}")
            response = requests.post(endpoint, json=payload, headers=headers, timeout=120)
            logging.info(response.request.body)
            if response.status_code == 202:
                logging.info(f"Successfully sent payload to {endpoint}: {response.text}")
            else:
                logging.warning(f"Failed to send payload to {endpoint}: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending request to {endpoint}: {e}")

    def send_payload(self, application_id, payload):
        """
        Send a payload to all HTTP endpoints configured for the given application concurrently.

        :param application_id: ChirpStack application ID.
        :param payload: The data to send in the HTTP POST request.
        """
        endpoints_with_headers = self.http_integration.get_http_integrations(application_id)

        if not endpoints_with_headers:
            logging.warning(f"No HTTP endpoints found for application {application_id}.")
            return

        # Use ThreadPoolExecutor to send requests concurrently
        with ThreadPoolExecutor(max_workers=len(endpoints_with_headers)) as executor:
            futures = []
            for endpoint, headers_from_api in endpoints_with_headers:
                headers = {"Content-Type": "application/json",  # Default header
                           "Authorization": headers_from_api.get("Authorization-1", "")}  
                
                # Add Authorization headers if it's an HTTP endpoint
                if "channels" in endpoint:
                    headers["Content-Type"] = "application/json"
                    headers.update(headers_from_api)  # Merge headers from API
                
                # Submit the request to the executor
                future = executor.submit(self._send_single_request, endpoint, headers, payload)
                futures.append(future)
            
            # Wait for all futures to complete
            for future in as_completed(futures):
                try:
                    future.result()  # Check for exceptions
                except Exception as e:
                    logging.error(f"An error occurred while sending a request: {e}")

# Example usage
if __name__ == "__main__":
    channel = grpc.insecure_channel(config.CHIRPSTACK_HOST)

    sender = HttpSender(channel, config.AUTH_METADATA)

    application_id = "41a744f9-7e86-4d71-9d5a-bcb5da6ded0d"  # Replace with actual Application ID
    payload = {
        "device": "Oct9_dragino",
        "sensor": "GoliathCrane",
        "value": 42.7,
        "unit": "kg",
        "timestamp": "2025-02-18T12:00:00Z"
    }

    sender.send_payload(application_id, payload)