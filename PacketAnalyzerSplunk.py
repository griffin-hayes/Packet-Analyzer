import requests
import json
import time
from scapy.all import sniff
from scapy.layers.inet import IP

SPLUNK_URL = "http://prd-p-adirc.splunkcloud.com/en-US/manager/launcher/http-eventcollector#:8088"
SPLUNK_TOKEN = "Token goes here"

def send_to_splunk(data):
    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(SPLUNK_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print("Data sent to Splunk successfully.")
    else:
        print(f"Failed to send to Splunk: {response.status_code}")


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        alert_data = {
            'event': "Suspicious packet detected",
            'source_ip': ip_src,
            'protocol': packet[IP].proto,
            'timestamp': time.time()
        }
        send_to_splunk(alert_data)


sniff(prn=packet_callback, store=0)
