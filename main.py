#main.py


from client import MQTTClient
from broker import MQTTBroker

# Initialisation
broker = MQTTBroker()
client = MQTTClient()

# Step 1 : ClientHello
pke, rc = client.send_client_hello()

# Step 2 : BrokerHello
rb, ct_e, pks = broker.receive_client_hello(pke, rc)

# Step 3 : ClientCiphertext
ct_s = client.receive_broker_hello(rb, ct_e, pks)

# Step 4 : ClientFinished
all_messages = rc + rb + pke + ct_e + pks + ct_s
transcript = hashlib.sha256(all_messages).digest()
messages = transcript
client_hmac = client.send_client_finished(messages)

# Step 5 : Broker vérifie
broker.receive_client_ciphertext(ct_s)
auth_ok = broker.verify_client_finished(client_hmac, messages)

# Step 6 : BrokerFinished
if auth_ok:
    broker_hmac = broker.send_broker_finished(messages)
    success = client.verify_broker_finished(broker_hmac, messages)
    if success:
        print("\nKEM-MQTT Handshake completed successfully!")
    else:
        print("\n Handshake failed.")
