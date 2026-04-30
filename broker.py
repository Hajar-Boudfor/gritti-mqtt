import os
from pqcrypto.kem.kyber512 import generate_keypair, encapsulate, decapsulate
from crypto_utils import generate_nonce, compute_hmac, derive_key

class MQTTBroker:
    
    def __init__(self):
        print("=== MQTT BROKER ===")
        print("Broker: Generating long-term Kyber-512 key pair...")
        self.pks, self.sks = generate_keypair()
        self.ss_e = None
        self.ss_s = None
        self.key = None
        print("Broker: Keys generated.")

    def receive_client_hello(self, pke, rc):
        """Step 2 : Broker receives ClientHello and sends BrokerHello."""
        print("\nBroker: Received ClientHello.")
        rb = generate_nonce()
        ct_e, self.ss_e = encapsulate(pke)
        return rb, ct_e, self.pks

    def receive_client_ciphertext(self, ct_s):
        """Step 4 : Broker decapsulates ct_s to recover ss_s."""
        print("\nBroker: Received ClientCiphertext.")
        self.ss_s = decapsulate(ct_s, self.sks)
        self.key = derive_key(self.ss_e, self.ss_s)
        return self.ss_s

    def verify_client_finished(self, hmac_received, messages):
        """Step 5 : Broker verifies ClientFinished HMAC."""
        hmac_expected = compute_hmac(self.key, messages)
        if hmac_received != hmac_expected:
            print("Broker: Authentication FAILED. ")
            return False
        print("Broker: Client authenticated. ")
        return True

    def send_broker_finished(self, messages):
        """Step 6 : Broker sends BrokerFinished HMAC."""
        broker_hmac = compute_hmac(self.key, messages)
        print("Broker: Sending BrokerFinished HMAC.")
        return broker_hmac
