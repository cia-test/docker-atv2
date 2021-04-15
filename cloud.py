import time
import sys
import re
import json
import argparse
import uuid
import os
import threading
import paho.mqtt.client as mqtt

class NRFCloud(object):
    def __init__(self, hostname, port, ca_certs, certfile, keyfile):
        self.pl = None
        self.client = mqtt.Client(client_id='nrfcloud-py')
        self.client.tls_set(ca_certs=ca_certs, certfile=certfile, keyfile=keyfile)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_subscribe = self.on_subscribe
        self.client.on_publish = self.on_publish
        self.client.connect(hostname, port=port)

    def on_publish(self, client, userdata, mid):
        print(f"published {mid}")

    def start(self):
        self.client.loop_forever()

    def stop(self):
        self.client.disconnect()
        self.client.loop_stop()

    def on_connect(self, client, userdata, flags, rc):
        print("connected")
        self.client.subscribe("#")
        self.client.subscribe("$aws/#")
        print("connected2")

    def on_message(self, client, userdata, msg):
        print(f"Message: {msg.topic}: {msg.payload}")

    def on_disconnect(self, client, userdata, rc):
        print("disconnected")

    def on_subscribe(self, client, userdata, mid, granted_qos):
        print(f"subscribe success {granted_qos} {mid}")

def main(ca, cert, key):
    import socket
    print(socket.gethostname())
    try:
        nrfcloud = NRFCloud( 
            "dev.testncs.com", 18883,
            ca_certs=ca, 
            certfile=cert, 
            keyfile=key

        )
        nrfcloud.start()
    except KeyboardInterrupt:
        nrfcloud.stop()

if __name__ == '__main__':
	main("credentials/ca/cia-ca.pem",
         "credentials/cert/client1-cert-signed-by-cia.pem",
         "credentials/cert/client1-privkey.pem")