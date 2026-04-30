import os
from pqcrypto.kem.kyber512 import generate_keypair, encapsulate, decapsulate
from crypto_utils import generate_nonce, compute_hmac, derive_key

class MQTTClient:

    def __init__(self):
        print("=== MQTT CLIENT ===")
        self.pke = None
        self.ske = None
        self.ss_e = None
        self.ss_s = None
        self.key = None

    def send_client_hello(self):
        """Step 1 : Client generates ephemeral key pair and sends ClientHello."""
        print("\nClient: Generating ephemeral key pair...")
        self.pke, self.ske = generate_keypair()
        rc = generate_nonce()
        print("Client: Sending ClientHello.")
        return self.pke, rc

    def receive_broker_hello(self, rb, ct_e, pks):
        """Step 3 : Client decapsulates ct_e and encapsulates ss_s."""
        print("\nClient: Received BrokerHello.")
        # Decapsulate ephemeral secret
        self.ss_e = decapsulate(ct_e, self.ske)
        print("Client: Decapsulated ephemeral secret ss_e.")
        # Encapsulate static secret with broker's long-term public key
        # cert[pks] simplified to pks directly (Gritti skeleton approach)
        ct_s, self.ss_s = encapsulate(pks)
        print("Client: Encapsulated static secret ss_s.")
        # Derive shared key
        self.key = derive_key(self.ss_e, self.ss_s)
        print("Client: Session key derived.")
        return ct_s

    def send_client_finished(self, messages):
        """Step 4 : Client sends ClientFinished HMAC."""
        client_hmac = compute_hmac(self.key, messages)
        print("Client: Sending ClientFinished HMAC.")
        return client_hmac

    def verify_broker_finished(self, hmac_received, messages):
        """Step 6 : Client verifies BrokerFinished HMAC."""
        hmac_expected = compute_hmac(self.key, messages)
        if hmac_received != hmac_expected:
            print("Client: Broker authentication FAILED.")
            return False
        print("Client: Broker authenticated.")
        return True
