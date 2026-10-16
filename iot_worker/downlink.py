import logging
from iot_worker.key_rotation import KeyManager, SharedKey, SensorCrypto
from binascii import hexlify
from iot_worker.device_manager import device_manager
import js2py
import config
from iot_worker.send_http_request import HttpSender
import grpc
import json
import paho.mqtt.client as mqtt

MQTT_BROKER = config.mqtt  # Or use the container hostname if running elsewhere
MQTT_PORT = 1883
MQTT_KEEPALIVE = config.keepalive  # Keep-alive interval in seconds
MQTT_USERNAME = None  # Set if using authentication
MQTT_PASSWORD = None


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# gRPC Channel Setup
channel = grpc.insecure_channel(config.CHIRPSTACK_HOST)
sender = HttpSender(channel, config.AUTH_METADATA)

# Initialize UA Key Manager (generates private/public key pair)
ua_key_manager = KeyManager()
last_rotation_time = 0  # Timestamp for last key rotation

# Store device-specific encryption keys
device_public_keys = {}  # Example: {"2cf7f12052608e69": <ED public key>}
device_crypto = {}  # Stores SensorCrypto instances keyed by DevEUI

def get_device_codec(dev_eui):
    """Find the codec for a device based on dev_eui."""
    try:
        for device_name, device_info in device_manager.all_devices.items():
            if device_info.get("euid") == dev_eui:
                logging.debug(f"Device {dev_eui} matched with {device_name}, using codec: {device_info.get('codec')}")
                return device_info.get("codec")
        logging.warning(f"No codec found for device {dev_eui}")
        return None
    except Exception as e:
        logging.error(f"Error fetching codec for device {dev_eui}: {e}")
        return None
    
def get_application_id(dev_eui):
    """Find the application ID for a device based on dev_eui."""
    try:
        for device_name, device_info in device_manager.all_devices.items():
            if device_info.get("euid") == dev_eui:
                app_id = device_info.get("application_id")
                logging.debug(f"Device {dev_eui} matched with {device_name}, using application_id: {app_id}")
                return app_id
        logging.warning(f"No application ID found for device {dev_eui}")
        return None
    except Exception as e:
        logging.error(f"Error fetching application ID for device {dev_eui}: {e}")
        return None
class DownlinkReassembler:
    """Handles reassembly of segmented downlink messages."""
    
    MAX_SEGMENT_LENGTH = 128  # Adjust as needed
    
    def __init__(self):
        """Initialize segmented message tracking."""
        self.segmented_message = {
            "type": None,
            "total": 0,
            "received": 0,
            "payload": ""
        }

    def reassemble_segment(self, segment: str) -> str:
        """
        Processes incoming segments and reassembles the full message when all parts are received.

        :param segment: The received segment string.
        :return: The full reassembled message when complete, otherwise an empty string.
        """
        logging.debug(f"Processing segment: {segment}")

        if segment.startswith("SEG"):
            try:
                # Extract header and payload
                header, payload = segment.split(":", 1)
                header = header[3:]  # Remove "SEG" prefix
                seg_num, total_segments = map(int, header.split("/"))

                # Initialize segmented message tracking if it's the first segment
                if self.segmented_message["type"] is None:
                    self.segmented_message["type"] = "PUBKEY"
                    self.segmented_message["total"] = total_segments
                    self.segmented_message["received"] = 0
                    self.segmented_message["payload"] = ""

                # Append the payload
                self.segmented_message["payload"] += payload
                self.segmented_message["received"] += 1

                logging.info(f"Received segment {seg_num}/{total_segments}")

                # If all segments are received, return the full message
                if self.segmented_message["received"] == self.segmented_message["total"]:
                    full_message = self.segmented_message["payload"]

                    # Reset for the next segmented message
                    self.segmented_message = {
                        "type": None,
                        "total": 0,
                        "received": 0,
                        "payload": ""
                    }

                    logging.info("Reassembly complete. Returning full message.")
                    return full_message

            except ValueError as ve:
                logging.error(f"Error parsing segment header: {ve}", exc_info=True)
            except Exception as e:
                logging.error(f"Unexpected error during reassembly: {e}", exc_info=True)

        else:
            logging.debug("Received a non-segmented message.")
            return segment  # Return non-segmented messages as-is

        return ""  # Return empty if reassembly is incomplete
    
def is_valid_hex(s):
    try:
        bytes.fromhex(s)  # Try converting it to bytes
        return True
    except ValueError:
        return False

def process_downlink_packet(packet: str):
    """
    Processes a received downlink packet, extracts the necessary fields, and handles key updates or sensor data.

    :param packet: The downlink packet string.
    """
    global device_public_keys, device_crypto, ua_key_manager

    logging.info(f"Processing downlink packet: {packet}")
    
    try:
        # Assume packet format: "PORT:<port> RX:<data> DevEUI:<dev_eui>"
        port_index = packet.index("PORT:")
        data_index = packet.index("RX:")
        dev_eui_index = packet.index("DevEUI:")

        port_str = packet[port_index+5:data_index].strip()
        port = int(port_str)
        data = packet[data_index+3:dev_eui_index].strip()
        dev_eui = packet[dev_eui_index+7:].strip()

        # Remove any surrounding quotes
        if data.startswith("\""):
            data = data[1:]
        if data.endswith("\""):
            data = data[:-1]

    except Exception as e:
        logging.error(f"Error parsing downlink packet: {e}", exc_info=True)
        return

    if port == config.DL_UA_PUBLIC_KEY:
        logging.info(f"Received new UA public key on FPort 76 for device {dev_eui}: {data}")

    elif port == config.DL_KEYROTATION_SUCCESS:
        logging.info(f"Acknowledgement received on FPort 10 for device {dev_eui}: {data}")

    elif port == config.UL_ED_PUBLIC_KEY:
        logging.info(f"Received ED public key update on FPort 26 for device {dev_eui}: {data}")
        
        # Validate if data is a valid hex string
        if not is_valid_hex(data):
            logging.error(f"Invalid hex data received for device {dev_eui}: {data}")
            return  # Exit if invalid hex data
        
        try:
            # Convert hex to ASCII
            data_ascii = bytes.fromhex(data).decode("utf-8")
            logging.info(f"Converted hex data to ASCII for device {dev_eui}: {data_ascii}")
        except ValueError as e:
            logging.error(f"Failed to convert hex to ASCII for device {dev_eui}: {e}", exc_info=True)
            return  # Exit if conversion fail
        
        reassembler = DownlinkReassembler()
        new_ed_pub = None
        
        if data_ascii.startswith("SEG"):
            full_payload = reassembler.reassemble_segment(data_ascii)
            if full_payload and full_payload.startswith("PUBKEY:"):
                new_ed_pub = full_payload[7:]
                logging.info(f"Reassembled ED public key for device {dev_eui}: {new_ed_pub}")
        else:
            if data_ascii.startswith("PUBKEY:"):
                try:
                    # Split by ':IV:' to separate PUBKEY and IV
                    parts = data_ascii.split(":IV:")
                    print(f"Parts after split: {parts}")
                    # new_ed_pub = parts[0][7:].strip()  # Extract PUBKEY (skip 'PUBKEY:')
                    new_ed_pub = parts[0][7:].replace("PUBKEY:", "", 1).strip()
                    iv_dev = parts[1].strip() if len(parts) > 1 else None  # Extract IV if present

                    logging.info(f"ED public key update received for device {dev_eui}: {new_ed_pub}")
                    if iv_dev:
                        logging.info(f"IV update received for device {dev_eui}: {iv_dev}")
                except Exception as e:
                    logging.error(f"Failed to parse PUBKEY/IV for device {dev_eui}: {e}")

        if new_ed_pub and len(new_ed_pub) == 130:
            device_public_keys[dev_eui] = new_ed_pub
            try:
                sk = SharedKey(ua_key_manager.get_private_key(), new_ed_pub)
                shared_secret = sk.get_shared_secret()
                logging.info(f"Generated shared key for device {dev_eui}: {sk}")
                logging.info(f"Derived shared secret for device {dev_eui}: {shared_secret}")  # Convert bytes to hex for logging
                
                device_crypto[dev_eui] = SensorCrypto(sk.get_shared_secret(), iv_dev)
                logging.info(f"Initialized SensorCrypto for device {dev_eui}: {device_crypto[dev_eui]}")
            except Exception as e:
                logging.error(f"Error updating shared secret for device {dev_eui}: {e}", exc_info=True)
        else:
            logging.warning(f"Invalid ED public key length for device {dev_eui}: {len(new_ed_pub) // 2} bytes")

        
    else:
        # Assume sensor data on FPorts 1–25.
        if dev_eui not in device_crypto:
            logging.warning(f"No SensorCrypto available for device {dev_eui} -> cannot decrypt sensor data.")
            return

        sc = device_crypto[dev_eui]
        try:
            decrypted_data = sc.decrypt(data)
            if decrypted_data is None:
                logging.warning(f"Dropping uplink from {dev_eui}: CMAC/decryption failed.")
                return
            logging.info(f"Decrypted Sensor Data for device {dev_eui}: {decrypted_data}")
        except Exception as e:
            logging.error(f"Decryption failed for device {dev_eui}: {e}", exc_info=True)
            
        # Find codec for the device
        codec = get_device_codec(dev_eui)

        if codec:
            logging.debug(f"Device {dev_eui} found. Using codec: {codec}")
            # decoded_data = codec.decode(data_hex)  # Implement decoding logic
            # logger.info(f"Decoded Data: {decoded_data}")
        else:
            logging.warning(f"No codec found for device {dev_eui}.")

         # Convert decrypted data to a byte array (ASCII conversion)
        #bytes_array = [ord(c) for c in decrypted_data] if isinstance(decrypted_data, str) else list(decrypted_data)

         # Execute the JavaScript decoder
        try:
            # Get application ID dynamically
            application_id = get_application_id(dev_eui)
            if not application_id:
                logging.error(f"Application ID not found for device {dev_eui}, skipping processing.")
                return None
        
            # Initialize JavaScript environment
            js_decoder = js2py.EvalJs()

            # Execute the JavaScript decoder
            js_decoder.execute(codec)
            logging.info(f"js_decoder: {js_decoder}")

            # Decode bytes to a string before passing to JavaScript
            decoded_payload = decrypted_data.decode('utf-8')

            # Convert to a list of character codes (needed for JavaScript)
            char_codes = [ord(c) for c in decoded_payload]

            # Call the Decode function and send the dev_eui
            decoded_data = js_decoder.Decode(char_codes, dev_eui)
            logging.info(f"Decoded Data: {decoded_data}")
            
            # Ensure decoded_data is valid before sending
            if decoded_data:
                send_data(decoded_data, application_id)  # Send decoded data with dynamic application ID
                send_data_mqtt(decoded_data, dev_eui) # Send decoded data to MQTT

            else:
                logging.error("Decoded data is empty")
            return decoded_data
        
        except Exception as e:
            logging.error(f"Decoding failed for device {dev_eui}: {e}", exc_info=True)
            return None
'''
def send_data(decoded_data, application_id):
    """
    Sends the decoded data directly as the payload to ChirpStack using the dynamic Application ID.
    """
    try:
        # Convert JsObjectWrapper to a Python dict/list
        if isinstance(decoded_data, js2py.base.JsObjectWrapper):
            decoded_data = js2py.translate_js(decoded_data)  # Convert JS object to Python object
         # Ensure decoded_data is properly formatted as JSON
        json_payload = json.dumps(decoded_data)  # Convert list/dict to valid JSON string
        
        sender.send_payload(application_id, json_payload)  # Sending decoded_data as is
        logging.info(f"Payload sent successfully to application {application_id}: {decoded_data}")

    except Exception as e:
        logging.error(f"Failed to send payload to application {application_id}: {e}", exc_info=True) 
        '''



def send_data(decoded_data, application_id):
    """
    Sends the decoded data directly as the payload to ChirpStack using the dynamic Application ID.
    """
    try:
        # Convert JsObjectWrapper to a Python dict/list
        if isinstance(decoded_data, js2py.base.JsObjectWrapper):
            try:
                decoded_data = decoded_data.to_dict()  # Convert to Python dict
            except AttributeError:
                decoded_data = decoded_data.to_list()  # Convert to Python list if applicable

        # Ensure decoded_data is properly formatted as JSON
        json_payload = json.dumps(decoded_data, indent=2)  # Pretty-print for debugging
        
        # removing the extra added field of data in codec and sending it forward
        sender.send_payload(application_id, decoded_data['data'])
        logging.info(f"Payload sent successfully to application {application_id}: {decoded_data['data']}")

    except Exception as e:
        logging.error(f"Failed to send payload to application {application_id}: {e}", exc_info=True)
        
def send_data_mqtt(decoded_data, dev_eui):
    """
    Publishes decoded data to an MQTT topic using the dev_eui.

    :param decoded_data: Decoded sensor data (dict or list).
    :param dev_eui: Device EUI used to build the topic.
    """
    try:
        if not dev_eui:
            raise ValueError("Device EUI is missing.")
        
        # Convert JsObjectWrapper to a Python dict/list
        if isinstance(decoded_data, js2py.base.JsObjectWrapper):
            try:
                decoded_data = decoded_data.to_dict()
            except AttributeError:
                decoded_data = decoded_data.to_list()

        client = mqtt.Client()

        if MQTT_USERNAME and MQTT_PASSWORD:
            client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
            logging.info("Using MQTT credentials for authentication.")
        else:
            logging.info("Connecting to MQTT without authentication.")

        client.connect(MQTT_BROKER, MQTT_PORT, MQTT_KEEPALIVE)

        topic = f"Honeycomb/device/{dev_eui}" # Construct the topic using dev_eui
        
        if "data" not in decoded_data:
            logging.warning("Expected 'data' key missing in decoded_data. Sending entire payload.")
        
        # Ensure decoded_data is properly formatted as JSON
        payload = json.dumps(decoded_data['data'], indent=2)  

        result = client.publish(topic, payload)
        result.wait_for_publish()

        if result.is_published():
            logging.info(f"Published data to MQTT topic {topic}: {payload}")
        else:
            logging.warning(f"Failed to publish to MQTT topic {topic}")

        client.disconnect()

    except Exception as e:
        logging.error(f"MQTT publish failed for device {dev_eui}: {e}", exc_info=True)

