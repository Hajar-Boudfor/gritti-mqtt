import os
import oqs
from crypto_utils import generate_nonce, compute_hmac, derive_key

class MQTTBroker:

    def __init__(self):
        print("=== MQTT BROKER ===")
        print("Broker: Generating long-term Kyber-512 key pair...")
        self.kem = oqs.KeyEncapsulation('Kyber512')
        self.pks = self.kem.generate_keypair()
        self.sks = self.kem.export_secret_key()
        self.ss_e = None
        self.ss_s = None
        self.key = None
        print("Broker: Keys generated.")

    def receive_client_hello(self, pke, rc):
        print("\nBroker: Received ClientHello.")
        rb = generate_nonce()
        ct_e, self.ss_e = self.kem.encap_secret(pke)
        return rb, ct_e, self.pks

    def receive_client_ciphertext(self, ct_s):
        print("\nBroker: Received ClientCiphertext.")
        kem_s = oqs.KeyEncapsulation('Kyber512', secret_key=self.sks)
        self.ss_s = kem_s.decap_secret(ct_s)
        self.key = derive_key(self.ss_e, self.ss_s)
        return self.ss_s

    def verify_client_finished(self, hmac_received, messages):
        hmac_expected = compute_hmac(self.key, messages)
        if hmac_received != hmac_expected:
            print("Broker: Authentication FAILED.")
            return False
        print("Broker: Client authenticated.")
        return True

    def send_broker_finished(self, messages):
        broker_hmac = compute_hmac(self.key, messages)
        print("Broker: Sending BrokerFinished HMAC.")
        return broker_hmac
