
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))
import grpc
from concurrent import futures
import json
import bank_pb2
import bank_pb2_grpc

class BankService(bank_pb2_grpc.BankServicer):
    def __init__(self, bank_name):
        self.bank_name = bank_name
        self.accounts = self.load_bank_data()

    def load_bank_data(self):
        """Load account balances for the given bank from bank_data.json."""
        with open("bank_data.json", "r") as f:
            data = json.load(f)
        return data.get(self.bank_name, {})

    def GetBalance(self, request, context):
        """Returns the balance of an account."""
        account = request.account_number
        balance = self.accounts.get(account, 0.0)
        return bank_pb2.BalanceResponse(balance=balance)
    
    def ProcessTransaction(self, request, context):
        """Handles money transfers for the sender's bank and credits receiver bank when applicable."""

        # ✅ Step 1: Check if this is a credit transaction (funds coming from outside)
        if request.from_account == "SYSTEM":
            if request.to_account not in self.accounts:
                return bank_pb2.TransactionResponse(success=False, message="Invalid Receiver Account")

            self.accounts[request.to_account] += request.amount  # Credit the amount
            return bank_pb2.TransactionResponse(success=True, message="Funds credited successfully")

        # ✅ Step 2: Deduct funds from sender’s account (existing logic)
        if request.from_account not in self.accounts:
            return bank_pb2.TransactionResponse(success=False, message="Invalid Sender Account")

        if self.accounts[request.from_account] < request.amount:
            return bank_pb2.TransactionResponse(success=False, message="Insufficient funds")

        self.accounts[request.from_account] -= request.amount  # Deduct funds

        return bank_pb2.TransactionResponse(success=True, message="Amount deducted, waiting for receiver bank")


def serve(bank_name, port):
    """Start a secure bank server with TLS."""
    cert_path = f'../certs/bank/{bank_name.lower()}.crt'
    key_path = f'../certs/bank/{bank_name.lower()}.key'

    with open(key_path, 'rb') as f:
        private_key = f.read()
    with open(cert_path, 'rb') as f:
        certificate_chain = f.read()
    with open('../certs/ca/ca.crt', 'rb') as f:
        root_certificates = f.read()

    server_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True
    )


    # Create a gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    bank_pb2_grpc.add_BankServicer_to_server(BankService(bank_name), server)

    # Start the secure server
    server.add_secure_port(f"[::]:{port}", server_credentials)
    print("port=" + port)
    print(f"🚀 Secure Bank Server '{bank_name}' started on port {port}")

    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bank_server.py <BANK_NAME> <PORT>")
        sys.exit(1)

    bank_name = sys.argv[1]
    port = sys.argv[2]
    serve(bank_name, port)
