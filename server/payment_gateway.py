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
from interceptor import AuthorizationInterceptor, LoggingInterceptor, TransactionLoggingInterceptor

import logging

# Configure logging
logging.basicConfig(
    filename="transactions.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Secret key for signing JWT tokens (keep this secure!)
SECRET_KEY = "supersecretkey"

# Load bank-port mappings from JSON file
def load_bank_ports():
    print("Loading bank ports")
    try:
        with open("banks.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("Error: banks.json not found!")
        return {}

# Load users from JSON file at startup
def load_users():
    try:
        with open("users.json", "r") as file:
            data = json.load(file)
            users = {}
            for user in data["users"]:
                users[user["username"]] = {
                    "password": user["password"],
                    "bank_name": user["bank_name"],
                    "account_number": user["account_number"]
                }
            return users
    except FileNotFoundError:
        print("Error: users.json not found!")
        return {}

BANK_PORTS = load_bank_ports()
clients_db = load_users()  # Store registered clients
bank_stubs = {}  # Store gRPC connections to bank servers


# Add to payment_gateway.py at global level
active_tokens = {}  # Dictionary to track active tokens: {username: {token: expiry_time}}

def create_bank_stub(bank_name):
    """Create a secure gRPC connection to a bank server."""
    

    # 🔍 Debugging: Check if bank_name exists in BANK_PORTS
    if bank_name not in BANK_PORTS:
        print(f"❌ Error: Bank '{bank_name}' not found in BANK_PORTS!")
        return None
    
    print(f"✅ Bank '{bank_name}' found! Port = {BANK_PORTS[bank_name]}")  # ✅ Now printing bank port
    
    # ✅ Load the trusted CA certificate
    with open("ca.crt", "rb") as f:
        trusted_certs = f.read()
    
    # ✅ Create gRPC SSL/TLS credentials for connecting to banks
    secure_creds = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    
    # ✅ Establish secure connection to bank servers dynamically
    # ✅ Establish secure connection to bank servers dynamically
    bank_stub = bank_pb2_grpc.BankStub(
        grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", secure_creds)
    )
    print(f"🔗 Secure connection established with bank: {bank_name}")
    return bank_stub


def generate_jwt(username):
    """Generate a JWT token for authentication."""
    # Check if user already has an active token
    if username in active_tokens:
        # Check if any token is still valid
        current_time = datetime.datetime.utcnow()
        for token, expiry in active_tokens[username].items():
            if expiry > current_time:
                # Return existing token if still valid
                return token
    
    # Generate new token
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "username": username,
        "exp": expiration_time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    
    # Store in active tokens
    if username not in active_tokens:
        active_tokens[username] = {}
    active_tokens[username][token] = expiration_time
    
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
   

    # Modify AuthenticateClient method in PaymentGatewayService
    def AuthenticateClient(self, request, context):
        """Authenticates user and returns a JWT token."""
        print("Authenticating client is called")
        logging.info(f"🔑 Authentication attempt for user: {request.username} from {context.peer()}")
        user = clients_db.get(request.username)
        if not user or user["password"] != request.password:
            logging.warning(f"❌ Failed login attempt for user: {request.username} from {context.peer()}")
            return payment_gateway_pb2.AuthResponse(authenticated=False, token="")
        
        # Check if user already has a valid token
        username = request.username
        current_time = datetime.datetime.utcnow()
        if username in active_tokens:
            for token, expiry in active_tokens[username].items():
                if expiry > current_time:
                    logging.warning(f"⚠️ {username} attempted login with active session (rejected)")
                    return payment_gateway_pb2.AuthResponse(
                        authenticated=False, 
                        token="", 
                        message="Already logged in. Please log out first or wait for token expiration."
                    )
        
        # If no active token, generate a new one
        token = generate_jwt(username)
        logging.info(f"✅ {username} successfully authenticated from {context.peer()}")
        return payment_gateway_pb2.AuthResponse(authenticated=True, token=token)
    
    def ProcessPayment(self, request, context):
        """Handles payment transactions securely with enhanced logging."""
        client_ip = context.peer()
        username = "Unknown"
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        if token:
            username = verify_jwt(token)  # Extract username from JWT
        
        logging.info(f"✅ {username} (IP: {client_ip}) initiated payment of ₹{request.amount} to {request.to_account}")
        
        try:
            # Ensure sender has sufficient balance
            sender_details = clients_db.get(username, None)
            if not sender_details:
                logging.warning(f"❌ {username} attempted payment, but account not found.")
                context.abort(grpc.StatusCode.NOT_FOUND, "User account not found")
            
            sender_bank = sender_details["bank_name"]
            sender_account = sender_details["account_number"]
            receiver_account = request.to_account
            amount = request.amount
            
            # Verify sender's bank connection
            if sender_bank not in bank_stubs:
                bank_stubs[sender_bank] = create_bank_stub(sender_bank)
                logging.info(f"✅ Secure connection established with sender's bank: {sender_bank}")
            
            sender_bank_stub = bank_stubs[sender_bank]
            balance_response = sender_bank_stub.GetBalance(
                bank_pb2.BalanceRequest(account_number=sender_account)
            )
            
            if balance_response.balance < amount:
                logging.warning(f"❌ {username} attempted payment of ₹{amount} (Insufficient Funds)")
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Insufficient funds")
            
            # Deduct funds from sender
            deduct_response = sender_bank_stub.ProcessTransaction(
                bank_pb2.TransactionRequest(
                    from_account=sender_account,
                    to_account=receiver_account,
                    amount=amount
                )
            )
            
            if not deduct_response.success:
                logging.warning(f"❌ {username} payment of ₹{amount} failed: {deduct_response.message}")
                context.abort(grpc.StatusCode.ABORTED, "Transaction failed")
            
            # Identify receiver's bank
            receiver_bank = None
            for user, details in clients_db.items():
                if details["account_number"] == receiver_account:
                    receiver_bank = details["bank_name"]
                    break
            
            if not receiver_bank:
                logging.warning(f"❌ {username} attempted payment to non-existent account {receiver_account}")
                context.abort(grpc.StatusCode.NOT_FOUND, "Receiver account not found")
            
            # Verify receiver's bank connection
            if receiver_bank not in bank_stubs:
                 bank_stubs[receiver_bank] = create_bank_stub(receiver_bank)
                 logging.info(f"✅ Secure connection established with receiver's bank: {receiver_bank}")
            
            receiver_bank_stub = bank_stubs[receiver_bank]
            credit_response = receiver_bank_stub.ProcessTransaction(
                bank_pb2.TransactionRequest(
                    from_account="SYSTEM",
                    to_account=receiver_account,
                    amount=amount
                )
            )
            
            if not credit_response.success:
                logging.warning(f"❌ {username} payment of ₹{amount} to {receiver_account} failed: {credit_response.message}")
                context.abort(grpc.StatusCode.ABORTED, "Credit transaction failed")
            
            logging.info(f"✅ {username} sent ₹{amount} to {receiver_account} successfully")
            return payment_gateway_pb2.PaymentResponse(success=True, message="Transaction successful")
        
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                logging.warning(f"🔄 Retrying payment for {username}. Gateway unavailable.")
            logging.error(f"❌ Payment Failed: {e.code()} - {e.details()}")
            raise e
    
    def CheckBalance(self, request, context):
        """Returns the client's account balance securely using JWT authentication."""
        print("check balance is called")
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        client_ip = context.peer()
        
        username = verify_jwt(token) if token else None
        if not username or username not in clients_db:
            logging.warning(f"❌ Unauthorized balance check attempt from {client_ip}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        user_details = clients_db[username]
        bank_name = user_details["bank_name"]
        account_number = user_details["account_number"]
        
        if bank_name not in BANK_PORTS:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank {bank_name} not found)")
            context.abort(grpc.StatusCode.NOT_FOUND, "Bank not found")

        if bank_name not in bank_stubs:
            print("calling create bank stub")
            bank_stubs[bank_name] = create_bank_stub(bank_name)
            logging.info(f"✅ Secure connection established with sender's bank: {bank_name}")
            

        try:
            response = bank_stubs[bank_name].GetBalance(
                bank_pb2.BalanceRequest(account_number=account_number)
            )
            logging.info(f"✅ {username} from {client_ip} checked balance: ₹{response.balance}")
            return payment_gateway_pb2.BalanceResponse(balance=response.balance)
        except grpc.RpcError as e:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank service unavailable)")
            context.abort(grpc.StatusCode.UNAVAILABLE, "Bank service unavailable")

def serve():
    try:
        # Load SSL/TLS Credentials
        with open("payment_gateway.crt", "rb") as f:
            server_cert = f.read()
        with open("payment_gateway.key", "rb") as f:
            server_key = f.read()

        # Configure SSL/TLS for the gRPC Server
        server_credentials = grpc.ssl_server_credentials([(server_key, server_cert)])

        # Start Secure gRPC Server with interceptors for authorization and logging
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=[
                AuthorizationInterceptor(),
                LoggingInterceptor(),
                TransactionLoggingInterceptor()
            ]
        )
        
        # Add the service to the server
        payment_gateway_pb2_grpc.add_PaymentGatewayServicer_to_server(PaymentGatewayService(), server)

        # Add secure port with TLS
        server.add_secure_port("[::]:50052", server_credentials)
        logging.info("🚀 Secure Payment Gateway started on port 50052 (TLS & Interceptors Enabled)")
        print("🚀 Secure Payment Gateway started on port 50052 (TLS & Interceptors Enabled)")
        
        server.start()
        server.wait_for_termination()
    except Exception as e:
        logging.critical(f"❌ Failed to start server: {str(e)}")
        print(f"❌ Critical error: {str(e)}")

if __name__ == "__main__":
    serve()