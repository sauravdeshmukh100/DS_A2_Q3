import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))
# import grpc
# import json
# from concurrent import futures
# import payment_gateway_pb2
# import payment_gateway_pb2_grpc
# import bank_pb2
# import bank_pb2_grpc

# # Load bank-port mappings from JSON file
# def load_bank_ports():
#     try:
#         with open("banks.json", "r") as file:
#             return json.load(file)
#     except FileNotFoundError:
#         print("Error: banks.json not found!")
#         return {}

# BANK_PORTS = load_bank_ports()
# clients_db = {}  # Store registered clients
# bank_stubs = {}  # Store gRPC connections to bank servers

# # Load users from JSON file at startup
# def load_users():
#     global clients_db
#     try:
#         with open("users.json", "r") as file:
#             data = json.load(file)
#             for user in data["users"]:
#                 clients_db[user["username"]] = {
#                     "password": user["password"],
#                     "bank_name": user["bank_name"],
#                     "account_number": user["account_number"]
#                 }
#     except FileNotFoundError:
#         print("Error: users.json not found!")

# load_users()  # Preload users

# class PaymentGatewayService(payment_gateway_pb2_grpc.PaymentGatewayServicer):
#     def AuthenticateClient(self, request, context):
#         user = clients_db.get(request.username)
#         if not user or user["password"] != request.password:
#             return payment_gateway_pb2.AuthResponse(authenticated=False, token="")
#         return payment_gateway_pb2.AuthResponse(authenticated=True, token=f"valid-{request.username}")
    
#     def ProcessPayment(self, request, context):
#         """Handles cross-bank transactions correctly."""
        
#         # ✅ Step 1: Authenticate the user
#         username = request.token.split("-")[1] if request.token.startswith("valid-") else None
#         if not username or username not in clients_db:
#             return payment_gateway_pb2.PaymentResponse(success=False, message="Unauthorized request")

#         # ✅ Step 2: Get sender & receiver details
#         sender_details = clients_db[username]
#         sender_bank = sender_details["bank_name"]
#         sender_account = sender_details["account_number"]
#         receiver_account = request.to_account

#         # ✅ Step 3: Find the receiver's bank
#         receiver_bank = None
#         for user, details in clients_db.items():
#             if details["account_number"] == receiver_account:
#                 receiver_bank = details["bank_name"]
#                 break

#         if not receiver_bank:
#             return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver account not found")

#         # ✅ Step 4: Ensure banks are registered
#         if sender_bank not in BANK_PORTS or receiver_bank not in BANK_PORTS:
#             return payment_gateway_pb2.PaymentResponse(success=False, message="Bank not found")

#         if sender_bank not in bank_stubs:
#             bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))

#         if receiver_bank not in bank_stubs:
#             bank_stubs[receiver_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[receiver_bank]}"))

#         # ✅ Step 5: Deduct funds from sender’s bank
#         try:
#             deduct_response = bank_stubs[sender_bank].ProcessTransaction(
#                 bank_pb2.TransactionRequest(
#                     from_account=sender_account,
#                     to_account=receiver_account,  # Just for logging, won't be processed here
#                     amount=request.amount
#                 )
#             )
#             if not deduct_response.success:
#                 return payment_gateway_pb2.PaymentResponse(success=False, message=f"Deduction failed: {deduct_response.message}")
#         except grpc.RpcError as e:
#             return payment_gateway_pb2.PaymentResponse(success=False, message=f"Transaction failed: {e.details()}")

#         # ✅ Step 6: Credit funds to receiver’s bank
#         try:
#             credit_response = bank_stubs[receiver_bank].ProcessTransaction(
#                 bank_pb2.TransactionRequest(
#                     from_account="SYSTEM",  # Indicating system deposit
#                     to_account=receiver_account,
#                     amount=request.amount
#                 )
#             )
#             if not credit_response.success:
#                 # ❌ Step 7: Refund if credit fails
#                 bank_stubs[sender_bank].ProcessTransaction(
#                     bank_pb2.TransactionRequest(
#                         from_account="SYSTEM",
#                         to_account=sender_account,
#                         amount=request.amount
#                     )
#                 )
#                 return payment_gateway_pb2.PaymentResponse(success=False, message="Credit failed, funds refunded")

#         except grpc.RpcError as e:
#             # ❌ Step 7: Refund if receiver bank is unreachable
#             bank_stubs[sender_bank].ProcessTransaction(
#                 bank_pb2.TransactionRequest(
#                     from_account="SYSTEM",
#                     to_account=sender_account,
#                     amount=request.amount
#                 )
#             )
#             return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver bank unavailable, funds refunded")

#         return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")

#     # def ProcessPayment(self, request, context):
#     #     username = request.token.split("-")[1] if request.token.startswith("valid-") else None
#     #     if not username or username not in clients_db:
#     #         return payment_gateway_pb2.PaymentResponse(success=False, message="Unauthorized request")

#     #     sender_details = clients_db[username]
#     #     sender_bank = sender_details["bank_name"]
#     #     sender_account = sender_details["account_number"]

#     #     if sender_bank not in BANK_PORTS:
#     #         return payment_gateway_pb2.PaymentResponse(success=False, message="Bank not found")

#     #     if sender_bank not in bank_stubs:
#     #         bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))

#     #     try:
#     #         response = bank_stubs[sender_bank].ProcessTransaction(
#     #             bank_pb2.TransactionRequest(
#     #                 from_account=sender_account,
#     #                 to_account=request.to_account,
#     #                 amount=request.amount
#     #             )
#     #         )
#     #         return payment_gateway_pb2.PaymentResponse(success=response.success, message=response.message)
#     #     except grpc.RpcError as e:
#     #         return payment_gateway_pb2.PaymentResponse(success=False, message=f"Transaction failed: {e.details()}")

#     # def CheckBalance(self, request, context):
#     #     #print("account no is " + request.account_number)
#     #     username = request.token.split("-")[1] if request.token.startswith("valid-") else None
#     #     if not username or username not in clients_db:
#     #         return payment_gateway_pb2.BalanceResponse(balance=-1)

#     #     user_details = clients_db[username]
#     #     bank_name = user_details["bank_name"]
#     #     account_number = user_details["account_number"]

#     #     if bank_name not in BANK_PORTS:
#     #         return payment_gateway_pb2.BalanceResponse(balance=-1)

#     #     if bank_name not in bank_stubs:
#     #         bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[bank_name]}"))

#     #     try:
#     #         response = bank_stubs[bank_name].GetBalance(
#     #             bank_pb2.BalanceRequest(account_number=account_number)
#     #         )
#     #         return payment_gateway_pb2.BalanceResponse(balance=response.balance)
#     #     except grpc.RpcError as e:
#     #         return payment_gateway_pb2.BalanceResponse(balance=-1)


#     def CheckBalance(self, request, context):
#         """Returns the client's account balance."""
        
#         # ✅ Step 1: Authenticate the user
#         username = request.token.split("-")[1] if request.token.startswith("valid-") else None
#         if not username or username not in clients_db:
#             return payment_gateway_pb2.BalanceResponse(balance=-1)

#         # ✅ Step 2: Get the client's bank details
#         user_details = clients_db[username]
#         bank_name = user_details["bank_name"]
#         account_number = user_details["account_number"]

#         # ✅ Step 3: Ensure the bank is registered
#         if bank_name not in BANK_PORTS:
#             return payment_gateway_pb2.BalanceResponse(balance=-1)

#         if bank_name not in bank_stubs:
#             bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[bank_name]}"))

#         # ✅ Step 4: Query the bank server for balance
#         try:
#             response = bank_stubs[bank_name].GetBalance(
#                 bank_pb2.BalanceRequest(account_number=account_number)
#             )
#             return payment_gateway_pb2.BalanceResponse(balance=response.balance)
#         except grpc.RpcError as e:
#             return payment_gateway_pb2.BalanceResponse(balance=-1)

# def serve():
#     server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
#     payment_gateway_pb2_grpc.add_PaymentGatewayServicer_to_server(PaymentGatewayService(), server)
#     server.add_insecure_port("[::]:50052")
#     print("🚀 Payment Gateway started on port 50052")
#     server.start()
#     server.wait_for_termination()

# if __name__ == "__main__":
#     serve()





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

# Secret key for signing JWT tokens (keep this secure!)
SECRET_KEY = "supersecretkey"

# Load bank-port mappings from JSON file
def load_bank_ports():
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
    """Verify the JWT token and extract the username."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

class PaymentGatewayService(payment_gateway_pb2_grpc.PaymentGatewayServicer):
    def AuthenticateClient(self, request, context):
        """Authenticates user and returns a JWT token."""
        user = clients_db.get(request.username)
        if not user or user["password"] != request.password:
            return payment_gateway_pb2.AuthResponse(authenticated=False, token="")
        
        # ✅ Generate JWT token for authentication
        token = generate_jwt(request.username)
        return payment_gateway_pb2.AuthResponse(authenticated=True, token=token)

    def ProcessPayment(self, request, context):
        """Handles payment transactions securely using JWT authentication."""
        
        # ✅ Step 1: Authenticate user via JWT
        username = verify_jwt(request.token)
        if not username or username not in clients_db:
            return payment_gateway_pb2.PaymentResponse(success=False, message="Unauthorized request")

        # ✅ Step 2: Get sender & receiver details
        sender_details = clients_db[username]
        sender_bank = sender_details["bank_name"]
        sender_account = sender_details["account_number"]
        receiver_account = request.to_account

        # ✅ Step 3: Find receiver's bank
        receiver_bank = None
        for user, details in clients_db.items():
            if details["account_number"] == receiver_account:
                receiver_bank = details["bank_name"]
                break

        if not receiver_bank:
            return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver account not found")

        # ✅ Step 4: Ensure banks are registered
        if sender_bank not in BANK_PORTS or receiver_bank not in BANK_PORTS:
            return payment_gateway_pb2.PaymentResponse(success=False, message="Bank not found")

        if sender_bank not in bank_stubs:
            # with open("ca.crt", "rb") as f:
            #     trusted_certs = f.read()
            # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
            # bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[sender_bank]}", secure_creds))
            bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))


        if receiver_bank not in bank_stubs:
            # with open("ca.crt", "rb") as f:
            #     trusted_certs = f.read()
            # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
            # bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[sender_bank]}", secure_creds))
            bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))


        # ✅ Step 5: Deduct funds from sender’s bank
        try:
            deduct_response = bank_stubs[sender_bank].ProcessTransaction(
                bank_pb2.TransactionRequest(
                    from_account=sender_account,
                    to_account=receiver_account,  
                    amount=request.amount
                )
            )
            if not deduct_response.success:
                return payment_gateway_pb2.PaymentResponse(success=False, message=f"Deduction failed: {deduct_response.message}")
        except grpc.RpcError as e:
            return payment_gateway_pb2.PaymentResponse(success=False, message=f"Transaction failed: {e.details()}")

        # ✅ Step 6: Credit funds to receiver’s bank
        try:
            credit_response = bank_stubs[receiver_bank].ProcessTransaction(
                bank_pb2.TransactionRequest(
                    from_account="SYSTEM",  
                    to_account=receiver_account,
                    amount=request.amount
                )
            )
            if not credit_response.success:
                bank_stubs[sender_bank].ProcessTransaction(
                    bank_pb2.TransactionRequest(
                        from_account="SYSTEM",
                        to_account=sender_account,
                        amount=request.amount
                    )
                )
                return payment_gateway_pb2.PaymentResponse(success=False, message="Credit failed, funds refunded")

        except grpc.RpcError as e:
            bank_stubs[sender_bank].ProcessTransaction(
                bank_pb2.TransactionRequest(
                    from_account="SYSTEM",
                    to_account=sender_account,
                    amount=request.amount
                )
            )
            return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver bank unavailable, funds refunded")

        return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")

    def CheckBalance(self, request, context):
        """Returns the client's account balance securely using JWT authentication."""
        
        # ✅ Step 1: Authenticate the user
        
        metadata = dict(context.invocation_metadata())  # ✅ Extract metadata
        token = metadata.get("authorization", None)  # ✅ Read JWT token from metadata
        username = verify_jwt(token)  # ✅ Now, verify the token

        #username = verify_jwt(request.token)
        if not username or username not in clients_db:
            return payment_gateway_pb2.BalanceResponse(balance=-1)

        # ✅ Step 2: Get the client's bank details
        user_details = clients_db[username]
        bank_name = user_details["bank_name"]
        account_number = user_details["account_number"]

        # ✅ Step 3: Ensure the bank is registered
        if bank_name not in BANK_PORTS:
            return payment_gateway_pb2.BalanceResponse(balance=-1)

        if bank_name not in bank_stubs:
        #     with open("ca.crt", "rb") as f:
        #         trusted_certs = f.read()
        # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
        # bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", secure_creds))
            bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[bank_name]}"))

        # ✅ Step 4: Query the bank server for balance
        try:
            response = bank_stubs[bank_name].GetBalance(
                bank_pb2.BalanceRequest(account_number=account_number)
            )
            return payment_gateway_pb2.BalanceResponse(balance=response.balance)
        except grpc.RpcError as e:
            return payment_gateway_pb2.BalanceResponse(balance=-1)

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
