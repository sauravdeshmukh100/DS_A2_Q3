
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


    # def ProcessTransaction(self, request, context):
    #     """Handles money transfers between accounts."""
    #     if request.from_account not in self.accounts or request.to_account not in self.accounts:
    #         return bank_pb2.TransactionResponse(success=False, message="Invalid Account")

    #     if self.accounts[request.from_account] < request.amount:
    #         return bank_pb2.TransactionResponse(success=False, message="Insufficient funds")

    #     self.accounts[request.from_account] -= request.amount
    #     self.accounts[request.to_account] += request.amount

    #     return bank_pb2.TransactionResponse(success=True, message="Transaction successful")

def serve(bank_name, port):
    """Start the bank server with the specified bank name and port."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    bank_pb2_grpc.add_BankServicer_to_server(BankService(bank_name), server)
    server.add_insecure_port(f"[::]:{port}")
    print(f"🚀 Bank Server '{bank_name}' started on port {port}")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bank_server.py <BANK_NAME> <PORT>")
        sys.exit(1)

    bank_name = sys.argv[1]
    port = sys.argv[2]
    serve(bank_name, port)
