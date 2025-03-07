import payment_gateway_pb2
import payment_gateway_pb2_grpc
#import bank_pb2
#import bank_pb2_grpc

clients_db = {}  # Store registered clients
bank_stubs = {}  # Store gRPC connections to bank servers

class PaymentGatewayService(payment_gateway_pb2_grpc.PaymentGatewayServicer):
    def RegisterClient(self, request, context):
        if request.username in clients_db:
            return payment_gateway_pb2.ClientRegistrationResponse(success=False, message="User already exists")
        
        clients_db[request.username] = {
            "password": request.password,
            "bank_name": request.bank_name,
            "account_number": request.account_number
        }
        return payment_gateway_pb2.ClientRegistrationResponse(success=True, message="Registration successful")

    def AuthenticateClient(self, request, context):
        user = clients_db.get(request.username)
        if not user or user["password"] != request.password:
            return payment_gateway_pb2.AuthResponse(authenticated=False, token="")

        return payment_gateway_pb2.AuthResponse(authenticated=True, token=f"valid-{request.username}")

    def ProcessPayment(self, request, context):
        if not request.token.startswith("valid-"):
            return payment_gateway_pb2.PaymentResponse(success=False, message="Unauthorized")

        bank_name = clients_db[request.token.split("-")[1]]["bank_name"]
        if bank_name not in bank_stubs:
            bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.insecure_channel("localhost:50051"))

        response = bank_stubs[bank_name].ProcessTransaction(
            bank_pb2.TransactionRequest(
                from_account=request.from_account,
                to_account=request.to_account,
                amount=request.amount
            )
        )

        return payment_gateway_pb2.PaymentResponse(success=response.success, message=response.message)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    payment_gateway_pb2_grpc.add_PaymentGatewayServicer_to_server(PaymentGatewayService(), server)
    server.add_insecure_port("[::]:50052")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()





# def ProcessPayment(self, request, context):
    #     """Handles payment transactions securely using JWT authentication."""
        
    #     # ✅ Step 1: Authenticate user via JWT
    #     username = verify_jwt(request.token)
    #     if not username or username not in clients_db:
    #         return payment_gateway_pb2.PaymentResponse(success=False, message="Unauthorized request")

    #     # ✅ Step 2: Get sender & receiver details
    #     sender_details = clients_db[username]
    #     sender_bank = sender_details["bank_name"]
    #     sender_account = sender_details["account_number"]
    #     receiver_account = request.to_account

    #     # ✅ Step 3: Find receiver's bank
    #     receiver_bank = None
    #     for user, details in clients_db.items():
    #         if details["account_number"] == receiver_account:
    #             receiver_bank = details["bank_name"]
    #             break

    #     if not receiver_bank:
    #         return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver account not found")

    #     # ✅ Step 4: Ensure banks are registered
    #     if sender_bank not in BANK_PORTS or receiver_bank not in BANK_PORTS:
    #         return payment_gateway_pb2.PaymentResponse(success=False, message="Bank not found")

    #     if sender_bank not in bank_stubs:
    #         # with open("ca.crt", "rb") as f:
    #         #     trusted_certs = f.read()
    #         # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    #         # bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[sender_bank]}", secure_creds))
    #         bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))


    #     if receiver_bank not in bank_stubs:
    #         # with open("ca.crt", "rb") as f:
    #         #     trusted_certs = f.read()
    #         # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    #         # bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[sender_bank]}", secure_creds))
    #         bank_stubs[sender_bank] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[sender_bank]}"))


    #     # ✅ Step 5: Deduct funds from sender’s bank
    #     try:
    #         deduct_response = bank_stubs[sender_bank].ProcessTransaction(
    #             bank_pb2.TransactionRequest(
    #                 from_account=sender_account,
    #                 to_account=receiver_account,  
    #                 amount=request.amount
    #             )
    #         )
    #         if not deduct_response.success:
    #             return payment_gateway_pb2.PaymentResponse(success=False, message=f"Deduction failed: {deduct_response.message}")
    #     except grpc.RpcError as e:
    #         return payment_gateway_pb2.PaymentResponse(success=False, message=f"Transaction failed: {e.details()}")

    #     # ✅ Step 6: Credit funds to receiver’s bank
    #     try:
    #         credit_response = bank_stubs[receiver_bank].ProcessTransaction(
    #             bank_pb2.TransactionRequest(
    #                 from_account="SYSTEM",  
    #                 to_account=receiver_account,
    #                 amount=request.amount
    #             )
    #         )
    #         if not credit_response.success:
    #             bank_stubs[sender_bank].ProcessTransaction(
    #                 bank_pb2.TransactionRequest(
    #                     from_account="SYSTEM",
    #                     to_account=sender_account,
    #                     amount=request.amount
    #                 )
    #             )
    #             return payment_gateway_pb2.PaymentResponse(success=False, message="Credit failed, funds refunded")

    #     except grpc.RpcError as e:
    #         bank_stubs[sender_bank].ProcessTransaction(
    #             bank_pb2.TransactionRequest(
    #                 from_account="SYSTEM",
    #                 to_account=sender_account,
    #                 amount=request.amount
    #             )
    #         )
    #         return payment_gateway_pb2.PaymentResponse(success=False, message="Receiver bank unavailable, funds refunded")

    #     return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")    



    def verify_jwt(token):
    """Verify the JWT token and extract the username."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    


    # import grpc
# import jwt
# import logging
# from datetime import datetime

# # Logging setup
# logging.basicConfig(filename="transactions.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# # Secret key for JWT validation
# SECRET_KEY = "supersecretkey"


# class AuthInterceptor(grpc.ServerInterceptor):
#     """gRPC Interceptor for centralized authentication and logging."""

#     def verify_jwt(self, token):
#         """Verify the JWT token and extract username."""
#         try:
#             payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#             return payload["username"]
#         except jwt.ExpiredSignatureError:
#             return None  # Token expired
#         except jwt.InvalidTokenError:
#             return None  # Invalid token

#     def intercept_service(self, continuation, handler_call_details):
#         """Intercept gRPC calls to enforce authentication and log requests."""

#         method = handler_call_details.method
        
#         # ✅ Allow `AuthenticateClient` request without a token
#         if "AuthenticateClient" in method:
#             return continuation(handler_call_details)

#         # ✅ Extract JWT token from metadata
#         metadata = dict(handler_call_details.invocation_metadata)
#         token = metadata.get("authorization", None)

#         username = self.verify_jwt(token) if token else None
#         if not username:
#             logging.warning(f"❌ Unauthorized access to {method} (Missing or Invalid Token)")
#             def abort_function(request, context):
#                 context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")
#             return grpc.unary_unary_rpc_method_handler(abort_function)

#         logging.info(f"✅ {username} called {method}")
#         return continuation(handler_call_details)




 # def CheckBalance(self, request, context):
    #     """Returns the client's account balance securely using JWT authentication."""
        
    #     # ✅ Step 1: Authenticate the user
        
    #     metadata = dict(context.invocation_metadata())  # ✅ Extract metadata
    #     token = metadata.get("authorization", None)  # ✅ Read JWT token from metadata
    #     username = verify_jwt(token)  # ✅ Now, verify the token

    #     #username = verify_jwt(request.token)
    #     if not username or username not in clients_db:
    #         return payment_gateway_pb2.BalanceResponse(balance=-1)

    #     # ✅ Step 2: Get the client's bank details
    #     user_details = clients_db[username]
    #     bank_name = user_details["bank_name"]
    #     account_number = user_details["account_number"]

    #     # ✅ Step 3: Ensure the bank is registered
    #     if bank_name not in BANK_PORTS:
    #         return payment_gateway_pb2.BalanceResponse(balance=-1)

    #     if bank_name not in bank_stubs:
    #     #     with open("ca.crt", "rb") as f:
    #     #         trusted_certs = f.read()
    #     # secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    #     # bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", secure_creds))
    #         bank_stubs[bank_name] = bank_pb2_grpc.BankStub(grpc.insecure_channel(f"localhost:{BANK_PORTS[bank_name]}"))

    #     # ✅ Step 4: Query the bank server for balance
    #     try:
    #         response = bank_stubs[bank_name].GetBalance(
    #             bank_pb2.BalanceRequest(account_number=account_number)
    #         )
    #         return payment_gateway_pb2.BalanceResponse(balance=response.balance)
    #     except grpc.RpcError as e:
    #         return payment_gateway_pb2.BalanceResponse(balance=-1)



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