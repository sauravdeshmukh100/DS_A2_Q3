import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))





import grpc
import json
import jwt
import datetime
from concurrent import futures
import payment_gateway_pb2
import payment_gateway_pb2_grpc
import bank_pb2
import bank_pb2_grpc
from interceptor import AuthInterceptor  # ✅ Import interceptor

import logging

logging.basicConfig(filename="transactions.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Secret key for signing JWT tokens (keep this secure!)
SECRET_KEY = "supersecretkey"

# Load bank-port mappings from JSON file
def load_bank_ports():
    print("loading bank ports")
    try:
        with open("banks.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("Error: banks.json not found!")
        return {}

BANK_PORTS = load_bank_ports()
clients_db = {}  # Store registered clients
bank_stubs = {}  # Store gRPC connections to bank servers

# Load users from JSON file at startup
def load_users():
    global clients_db
    try:
        with open("users.json", "r") as file:
            data = json.load(file)
            for user in data["users"]:
                clients_db[user["username"]] = {
                    "password": user["password"],
                    "bank_name": user["bank_name"],
                    "account_number": user["account_number"]
                }
    except FileNotFoundError:
        print("Error: users.json not found!")

load_users()  # Preload users

def generate_jwt(username):
    """Generate a JWT token for authentication."""
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    payload = {
        "username": username,
        "exp": expiration_time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def verify_jwt(token):
    """Verify the JWT token and extract the username. Refresh if expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        logging.warning("❌ Token expired. User must re-authenticate.")
        return "EXPIRED"
    except jwt.InvalidTokenError:
        return None
    

class PaymentGatewayService(payment_gateway_pb2_grpc.PaymentGatewayServicer):
    def AuthenticateClient(self, request, context):
        """Authenticates user and returns a JWT token."""
        print("request is " + request.username)
        user = clients_db.get(request.username)
        if not user or user["password"] != request.password:
            logging.warning(f"❌ Failed login attempt for user: {request.username}")
            return payment_gateway_pb2.AuthResponse(authenticated=False, token="")  # ❌ No token returned

        token = generate_jwt(request.username)  # ✅ Generate JWT token
        logging.info(f"✅ {request.username} successfully authenticated.")
        return payment_gateway_pb2.AuthResponse(authenticated=True, token=token)

    
    

    


    # def ProcessPayment(self, request, context):
    #     """Handles payment transactions securely using JWT authentication."""
    
    #      # ✅ Step 1: Extract JWT from metadata
    #     metadata = dict(context.invocation_metadata())
    #     token = metadata.get("authorization", None)
    #     print("token is " + token)
        
    #     # ✅ Step 2: Verify JWT
    #     username = verify_jwt(token) if token else None
    #     if not username or username not in clients_db:
    #         logging.warning(f"❌ Failed payment attempt (Unauthorized) by unknown user")
    #         context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

    #     # ✅ Step 3: Get sender & receiver details
    #     sender_details = clients_db[username]
    #     sender_bank = sender_details["bank_name"]
    #     sender_account = sender_details["account_number"]
    #     receiver_account = request.to_account
    #     amount = request.amount

    #     # ✅ Step 4: Ensure the sender has enough funds
    #     if sender_bank not in bank_stubs:
    #         bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(
    #             grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}")
    #         )
    #         logging.info(f"✅ Connected to sender's bank {sender_bank} at port {BANK_PORTS[sender_bank]}")

    #     if not sender_bank_stub:
    #         context.abort(grpc.StatusCode.NOT_FOUND, "Sender bank not found")

    #     balance_response = sender_bank_stub.GetBalance(
    #         bank_pb2.BalanceRequest(account_number=sender_account)
    #     )

    #     if balance_response.balance < amount:
    #         logging.warning(f"❌ {username} attempted ₹{amount} transfer to {receiver_account} (Failed: Insufficient Funds)")
    #         context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Insufficient funds")

    #     # ✅ Step 5: Deduct funds from sender’s bank
    #     deduct_response = sender_bank_stub.ProcessTransaction(
    #         bank_pb2.TransactionRequest(
    #             from_account=sender_account,
    #             to_account=receiver_account,
    #             amount=amount
    #         )
    #     )

    #     if not deduct_response.success:
    #         logging.warning(f"❌ {username} attempted ₹{amount} transfer to {receiver_account} (Failed: {deduct_response.message})")
    #         context.abort(grpc.StatusCode.ABORTED, "Transaction failed")

    #     # ✅ Step 6: Credit funds to receiver’s bank
    #     if receiver_account not in [details["account_number"] for details in clients_db.values()]:
    #         logging.warning(f"❌ {username} attempted transfer to non-existent account {receiver_account}")
    #         context.abort(grpc.StatusCode.NOT_FOUND, "Receiver account not found")

    #     receiver_bank = None
    #     print("in step 6")
    #     for user, details in clients_db.items():
    #         if details["account_number"] == receiver_account:
    #             receiver_bank = details["bank_name"]
    #             print("receiver bank is " + receiver_bank)
    #             break

    #     if not receiver_bank:
    #         logging.warning(f"❌ {username} sent ₹{amount} to {receiver_account} (Failed: Receiver bank not found)")
    #         context.abort(grpc.StatusCode.NOT_FOUND, "Receiver bank not found")

    #     receiver_bank_stub = bank_stubs.get(receiver_bank)
    #     if not receiver_bank_stub:
    #         context.abort(grpc.StatusCode.UNAVAILABLE, "Receiver bank unavailable")

    #     credit_response = receiver_bank_stub.ProcessTransaction(
    #         bank_pb2.TransactionRequest(
    #             from_account="SYSTEM",
    #             to_account=receiver_account,
    #             amount=amount
    #         )
    #     )

    #     if not credit_response.success:
    #         logging.warning(f"❌ {username} sent ₹{amount} to {receiver_account} (Failed: {credit_response.message})")
    #         context.abort(grpc.StatusCode.ABORTED, "Credit transaction failed")

    #     # ✅ Step 7: Log Successful Transaction
    #     logging.info(f"✅ {username} sent ₹{amount} to {receiver_account} (Success)")
        
    #     return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")

    def ProcessPayment(self, request, context):
        """Handles payment transactions securely using JWT authentication."""
        
        # ✅ Step 1: Extract JWT from metadata
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        print("token is " + str(token))
        
        # ✅ Step 2: Verify JWT
        username = verify_jwt(token) if token else None
        if not username or username not in clients_db:
            logging.warning(f"❌ Failed payment attempt (Unauthorized) by unknown user")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        # ✅ Step 3: Get sender & receiver details
        sender_details = clients_db[username]
        sender_bank = sender_details["bank_name"]
        sender_account = sender_details["account_number"]
        receiver_account = request.to_account
        amount = request.amount

        # ✅ Step 4: Ensure sender's bank is connected
        if sender_bank not in BANK_PORTS:
            context.abort(grpc.StatusCode.NOT_FOUND, "Sender bank not found")

        if sender_bank not in bank_stubs:
            bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(
                grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}")
            )
            logging.info(f"✅ Connected to sender's bank {sender_bank} at port {BANK_PORTS[sender_bank]}")

        sender_bank_stub = bank_stubs[sender_bank]

        # ✅ Step 5: Check if sender has enough funds
        balance_response = sender_bank_stub.GetBalance(
            bank_pb2.BalanceRequest(account_number=sender_account)
        )

        if balance_response.balance < amount:
            logging.warning(f"❌ {username} attempted ₹{amount} transfer to {receiver_account} (Failed: Insufficient Funds)")
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Insufficient funds")

        # ✅ Step 6: Deduct funds from sender
        deduct_response = sender_bank_stub.ProcessTransaction(
            bank_pb2.TransactionRequest(
                from_account=sender_account,
                to_account=receiver_account,
                amount=amount
            )
        )

        if not deduct_response.success:
            logging.warning(f"❌ {username} attempted ₹{amount} transfer to {receiver_account} (Failed: {deduct_response.message})")
            context.abort(grpc.StatusCode.ABORTED, "Transaction failed")

        # ✅ Step 7: Find receiver's bank
        if receiver_account not in [details["account_number"] for details in clients_db.values()]:
            logging.warning(f"❌ {username} attempted transfer to non-existent account {receiver_account}")
            context.abort(grpc.StatusCode.NOT_FOUND, "Receiver account not found")

        receiver_bank = None
        for user, details in clients_db.items():
            if details["account_number"] == receiver_account:
                receiver_bank = details["bank_name"]
                print("receiver bank is " + receiver_bank)
                break

        if not receiver_bank:
            logging.warning(f"❌ {username} sent ₹{amount} to {receiver_account} (Failed: Receiver bank not found)")
            context.abort(grpc.StatusCode.NOT_FOUND, "Receiver bank not found")

        # ✅ Step 8: Ensure receiver's bank is connected
        if receiver_bank not in BANK_PORTS:
            context.abort(grpc.StatusCode.NOT_FOUND, "Receiver bank not found")

        if receiver_bank not in bank_stubs:
            bank_stubs[receiver_bank] = bank_pb2_grpc.BankStub(
                grpc.insecure_channel(f"localhost:{BANK_PORTS[receiver_bank]}")
            )
            logging.info(f"✅ Connected to receiver's bank {receiver_bank} at port {BANK_PORTS[receiver_bank]}")

        receiver_bank_stub = bank_stubs[receiver_bank]

        # ✅ Step 9: Credit funds to receiver
        credit_response = receiver_bank_stub.ProcessTransaction(
            bank_pb2.TransactionRequest(
                from_account="SYSTEM",
                to_account=receiver_account,
                amount=amount
            )
        )

        if not credit_response.success:
            logging.warning(f"❌ {username} sent ₹{amount} to {receiver_account} (Failed: {credit_response.message})")
            context.abort(grpc.StatusCode.ABORTED, "Credit transaction failed")

        # ✅ Step 10: Log Successful Transaction
        logging.info(f"✅ {username} sent ₹{amount} to {receiver_account} (Success)")
        
        return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")
    
    def CheckBalance(self, request, context):
        """Returns the client's account balance securely using JWT authentication."""
        
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        print("token is " + token)
        
        username = verify_jwt(token) if token else None
        if not username or username not in clients_db:
            logging.warning(f"❌ Unauthorized balance check attempt")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        user_details = clients_db[username]
        bank_name = user_details["bank_name"]
        account_number = user_details["account_number"]
        print("bank name is " + bank_name)
        if bank_name not in BANK_PORTS:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank not found)")
            context.abort(grpc.StatusCode.NOT_FOUND, "Bank not found")

        # if bank_name not in bank_stubs:
        #     with open("ca.crt", "rb") as f:
        #         trusted_certs = f.read()
        #     secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
        #     bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", secure_creds))

        if bank_name not in bank_stubs:
            bank_stubs[bank_name] = bank_pb2_grpc.BankStub(
                grpc.insecure_channel(f"localhost:{BANK_PORTS[bank_name]}")
            )
            logging.info(f"✅ Connected to {bank_name} at port {BANK_PORTS[bank_name]}")


        try:
            response = bank_stubs[bank_name].GetBalance(
                bank_pb2.BalanceRequest(account_number=account_number)
            )
            logging.info(f"✅ {username} checked balance: ₹{response.balance}")
            return payment_gateway_pb2.BalanceResponse(balance=response.balance)
        except grpc.RpcError as e:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank service unavailable)")
            context.abort(grpc.StatusCode.UNAVAILABLE, "Bank service unavailable")
            

   




def serve():
    # ✅ Load SSL/TLS Credentials
    with open("server.key", "rb") as f:
        private_key = f.read()
    with open("server.crt", "rb") as f:
        certificate_chain = f.read()

    # ✅ Configure SSL/TLS for the gRPC Server
    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])

    # ✅ Start Secure gRPC Server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10),interceptors=[AuthInterceptor()])  # ✅ Create gRPC server with interceptor
    payment_gateway_pb2_grpc.add_PaymentGatewayServicer_to_server(PaymentGatewayService(), server)

    server.add_secure_port("[::]:50052", server_credentials)
    print("🚀 Secure Payment Gateway started on port 50052 (TLS & Interceptor Enabled)")
    
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
