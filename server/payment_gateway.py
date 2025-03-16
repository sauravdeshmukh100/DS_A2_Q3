import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))

import grpc
import json
import jwt
import datetime
import uuid
import time
import threading
from concurrent import futures
import payment_gateway_pb2
import payment_gateway_pb2_grpc
import bank_pb2
import bank_pb2_grpc
from interceptor import RegisterBankInterceptor , AuthorizationInterceptor, LoggingInterceptor, TransactionLoggingInterceptor

import logging

# Configure logging
logging.basicConfig(
    filename="transactions.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


# this at the global level so transactions persist across runs.
TRANSACTION_FILE = "transactions.json"  # JSON file to store transaction history
#transaction_lock = threading.Lock()  # Ensure thread-safe access to the file

# Store transaction states for 2PC
transaction_states = {}  # {transaction_id: {status, sender_prepared, receiver_prepared, etc.}}



BANKS_FILE = "banks.json"

def RegisterBank(self, request, context):
    """Handles bank registration from bank servers."""
    bank_name = request.bank_name
    port = request.port

    # Load existing banks.json (if exists)
    if os.path.exists(BANKS_FILE):
        with open(BANKS_FILE, "r") as file:
            try:
                banks = json.load(file)
            except json.JSONDecodeError:
                banks = {}
    else:
        banks = {}

    # Check if the bank is already registered
    if bank_name in banks:
        return bank_pb2.RegisterBankResponse(message="Bank already registered.")

    # Register the new bank
    banks[bank_name] = port
    with open(BANKS_FILE, "w") as file:
        json.dump(banks, file, indent=4)

    return bank_pb2.RegisterBankResponse(message="Bank registered successfully.")



# ✅ Load past transactions from file
try:
    with open(TRANSACTION_FILE, "r") as file:
        print("Loading transaction states")
        transaction_states = json.load(file)
        print(f"✅ Loaded {len(transaction_states)} previous transactions from {TRANSACTION_FILE}")
except (FileNotFoundError, json.JSONDecodeError):
    transaction_states = {}  # Initialize if file is missing or corrupted

# ✅ Function to persist transactions
def save_transaction_state():
    with open(TRANSACTION_FILE, "w") as file:
        json.dump(transaction_states, file, indent=4)

# Secret key for signing JWT tokens (keep this secure!)
SECRET_KEY = "supersecretkey"

# Timeout for 2PC operations (in seconds)
TRANSACTION_TIMEOUT = 5

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
    """Load users from JSON file and support multiple bank accounts per user."""
    try:
        with open("users.json", "r") as file:
            data = json.load(file)
            users = {}

            for user in data.get("users", []):  # ✅ Ensure "users" key exists
                username = user.get("username")
                password = user.get("password")
                bank_name = user.get("bank_name")
                account_number = user.get("account_number")

                if not username or not password or not bank_name or not account_number:
                    print(f"⚠️ Skipping invalid user entry: {user}")
                    continue  # ✅ Skip invalid entries

                if username not in users:
                    users[username] = {
                        "password": password,
                        "accounts": []  # ✅ Store multiple accounts per user
                    }

                # ✅ Append new bank account details to the user's account list
                users[username]["accounts"].append({
                    "bank_name": bank_name,
                    "account_number": account_number
                })

            return users
    except (FileNotFoundError, json.JSONDecodeError):
        print("❌ Error: users.json not found or invalid JSON format!")
        return {}

BANK_PORTS = load_bank_ports()
clients_db = load_users()  # Store registered clients
bank_stubs = {}  # Store gRPC connections to bank servers


# Add to payment_gateway.py at global level
active_tokens = {}  # Dictionary to track active tokens: {username: {token: expiry_time}}




def load_transaction_states():
    """Loads transaction states from a JSON file to restore previous transactions."""
    global transaction_states
    try:
        with open(TRANSACTION_FILE, "r") as file:
            transaction_states = json.load(file)  # Load JSON data
            logging.info(f"✅ Loaded {len(transaction_states)} previous transactions from {TRANSACTION_FILE}")
    except (FileNotFoundError, json.JSONDecodeError):
        logging.warning(f"⚠️ No previous transactions found. Starting fresh.")
        transaction_states = {}  # Initialize with an empty dictionary  

def create_bank_stub(bank_name):
    """Create a secure gRPC connection to a bank server."""
    

    # 🔍 Debugging: Check if bank_name exists in BANK_PORTS
    if bank_name not in BANK_PORTS:
        print(f"❌ Error: Bank '{bank_name}' not found in BANK_PORTS!")
        return None
    
    print(f"✅ Bank '{bank_name}' found! Port = {BANK_PORTS[bank_name]}")  # ✅ Now printing bank port

    # Load certificates for bank connection
    with open('../certs/payment/payment.key', 'rb') as f:
        private_key = f.read()
    with open('../certs/payment/payment.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('../certs/ca/ca.crt', 'rb') as f:
        root_certificates = f.read()
    
    # Create client credentials for connecting to bank
    client_credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain
    )
        
    # Create secure channel to bank
    # bank_channel = grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", client_credentials)
    # Create secure channel to bank with timeout options
    options = [('grpc.keepalive_timeout_ms', TRANSACTION_TIMEOUT * 1000)]
    bank_channel = grpc.secure_channel(f"localhost:{BANK_PORTS[bank_name]}", client_credentials, options=options)
    bank_stub = bank_pb2_grpc.BankStub(bank_channel)
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


def generate_transaction_id():
    """Generate a unique transaction ID."""
    return f"txn-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(time.time())}"


def verify_jwt(token):
    """Verify the JWT token and extract the username. Refresh if expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        logging.warning("❌ Token expired. User must re-authenticate.")
        return None
    except jwt.InvalidTokenError:
        return None
    

class PaymentGatewayService(payment_gateway_pb2_grpc.PaymentGatewayServicer):

    def RegisterBank(self, request, context):
        """Registers a bank with the Payment Gateway and updates banks.json."""
        print("inside register_bank")
        bank_name = request.bank_name
        bank_port = request.bank_port

        global BANK_PORTS  # Ensure we are modifying the global dictionary

        # Load the existing bank mappings
        try:
            with open("banks.json", "r") as file:
                BANK_PORTS = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            BANK_PORTS = {}  # Initialize if file is missing or corrupted

        # ✅ If bank is already registered, update its port
        if bank_name in BANK_PORTS:
            if BANK_PORTS[bank_name] == bank_port:
                logging.info(f"✅ {bank_name} is already registered on port {bank_port}.")
                return payment_gateway_pb2.RegisterBankResponse(success=True, message="Bank already registered.")
            else:
                logging.info(f"🔄 Updating port for {bank_name} from {BANK_PORTS[bank_name]} to {bank_port}.")
        
        # ✅ Register or update bank's port
        BANK_PORTS[bank_name] = bank_port

        # ✅ Save updated mappings to banks.json
        try:
            with open("banks.json", "w") as file:
                json.dump(BANK_PORTS, file, indent=4)
        except Exception as e:
            logging.error(f"❌ Failed to update banks.json: {str(e)}")
            context.abort(grpc.StatusCode.INTERNAL, "Failed to update bank records.")

        logging.info(f"✅ Registered/Updated bank: {bank_name} on port {bank_port}")
        return payment_gateway_pb2.RegisterBankResponse(success=True, message="Bank registered successfully.")



    # Modify AuthenticateClient method in PaymentGatewayService
    def AuthenticateClient(self, request, context):
        """Authenticates user and returns a JWT token."""
        print("Authenticating client is called")
        logging.info(f"🔑 Authentication attempt for user: {request.username} from {context.peer()}")

        user = clients_db.get(request.username)
        
        # ✅ Check if user exists and password matches
        if not user or user["password"] != request.password:
            logging.warning(f"❌ Failed login attempt for user: {request.username} from {context.peer()}")
            return payment_gateway_pb2.AuthResponse(authenticated=False, token="", message="Invalid username or password.")

        # ✅ Extract token from metadata (if provided)
        metadata = dict(context.invocation_metadata())
        existing_token = metadata.get("authorization", None)

        if existing_token:
            token_status = verify_jwt(existing_token)
            if token_status and token_status != "EXPIRED":
                print("User already has a valid token")
                logging.warning(f"⚠️ {request.username} attempted login with active session (rejected)")
                return payment_gateway_pb2.AuthResponse(
                    authenticated=False, 
                    token="", 
                    message="Already logged in. Please log out first or wait for token expiration."
                )

        # ✅ Check if user already has an active (non-expired) token
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

        # ✅ Generate a new token if no active session
        token = generate_jwt(username)
        logging.info(f"✅ {username} successfully authenticated from {context.peer()}")
        return payment_gateway_pb2.AuthResponse(authenticated=True, token=token)

    


    def LogoutClient(self, request, context):
        """Logs out the user by invalidating their active token."""
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        client_ip = context.peer()

        # ✅ Check if token is provided
        if not token:
            logging.warning(f"❌ Logout attempt without a token from {client_ip}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Missing token.")

        # ✅ Verify if the token is valid
        username = verify_jwt(token)
        print("username",username)
        if username is None or username == "EXPIRED":
            logging.warning(f"❌ Logout attempt with invalid/expired token from {client_ip}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or expired token.")
        
        # # ✅ Check if the token exists in active_tokens and invalidate it
        # if username in active_tokens or token in active_tokens[username]:   # written or not and 
        #     del active_tokens[username][token]  # Invalidate token
        #     logging.info(f"✅ {username} logged out successfully from {client_ip}.")
            
        #     # ✅ Store logout attempt in transactions.log
        #     transaction_entry = {
        #         "transaction_id": f"logout_{datetime.datetime.utcnow().timestamp()}",
        #         "username": username,
        #         "action": "logout",
        #         "timestamp": datetime.datetime.utcnow().isoformat(),
        #         "status": "Success"
        #     }
        #     # save_transaction(transaction_entry)

        return payment_gateway_pb2.LogoutResponse(success=True, message="Logout successful.")

        # # ✅ Handle case where user tries to log out but already logged out
        # logging.warning(f"⚠️ {username} attempted to log out but was already logged out from {client_ip}.")

        # transaction_entry = {
        #     "transaction_id": f"logout_{datetime.datetime.utcnow().timestamp()}",
        #     "username": username,
        #     "action": "logout",
        #     "timestamp": datetime.datetime.utcnow().isoformat(),
        #     "status": "Failed - Already logged out"
        # }
        # save_transaction(transaction_entry)

        return payment_gateway_pb2.LogoutResponse(success=False, message="Already logged out.")


    


    def prepare_transaction(self, transaction_id, bank_stub, account, amount, is_sender=True):
        """Prepare phase: Ask bank if it can lock funds for transaction."""
        try:
            # Set timeout for the gRPC call
            timeout = time.time() + TRANSACTION_TIMEOUT
            
            # Call prepare endpoint on bank
            bank_operation = "debit" if is_sender else "credit"
            prepare_request = bank_pb2.PrepareRequest(
                transaction_id=transaction_id,
                account_number=account,
                amount=amount,
                operation=bank_operation
            )
            
            # Make prepare call with timeout
            prepare_response = bank_stub.PrepareTransaction(
                prepare_request,
                timeout=TRANSACTION_TIMEOUT
            )
            
            return prepare_response.success, prepare_response.message
            
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                logging.error(f"❌ [TXN: {transaction_id}] Bank prepare timed out after {TRANSACTION_TIMEOUT}s")
                return False, f"Bank operation timed out after {TRANSACTION_TIMEOUT}s"
            else:
                logging.error(f"❌ [TXN: {transaction_id}] Bank prepare failed: {e.code()} - {e.details()}")
                return False, f"Bank operation failed: {e.details()}"
    
    def commit_transaction(self, transaction_id, bank_stub, account, amount, is_sender=True):
        """Commit phase: Tell bank to commit the transaction."""
        try:
            # Set timeout for the gRPC call
            timeout = time.time() + TRANSACTION_TIMEOUT
            
            # Call commit endpoint on bank
            bank_operation = "debit" if is_sender else "credit"
            commit_request = bank_pb2.CommitRequest(
                transaction_id=transaction_id,
                account_number=account,
                amount=amount,
                operation=bank_operation
            )
            
            # Make commit call with timeout
            commit_response = bank_stub.CommitTransaction(
                commit_request,
                timeout=TRANSACTION_TIMEOUT
            )
            
            return commit_response.success, commit_response.message
            
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                logging.error(f"❌ [TXN: {transaction_id}] Bank commit timed out after {TRANSACTION_TIMEOUT}s")
                return False, f"Bank operation timed out after {TRANSACTION_TIMEOUT}s"
            else:
                logging.error(f"❌ [TXN: {transaction_id}] Bank commit failed: {e.code()} - {e.details()}")
                return False, f"Bank operation failed: {e.details()}"
    
    def abort_transaction(self, transaction_id, bank_stub, account, amount, is_sender=True):
        """Abort phase: Tell bank to abort and release any locked funds."""
        try:
            # Set timeout for the gRPC call
            timeout = time.time() + TRANSACTION_TIMEOUT
            
            # Call abort endpoint on bank
            bank_operation = "debit" if is_sender else "credit"
            abort_request = bank_pb2.AbortRequest(
                transaction_id=transaction_id,
                account_number=account,
                amount=amount,
                operation=bank_operation
            )
            
            # Make abort call with timeout
            abort_response = bank_stub.AbortTransaction(
                abort_request,
                timeout=TRANSACTION_TIMEOUT
            )
            
            return abort_response.success, abort_response.message
            
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                logging.error(f"❌ [TXN: {transaction_id}] Bank abort timed out after {TRANSACTION_TIMEOUT}s")
                return False, f"Bank abort timed out after {TRANSACTION_TIMEOUT}s"
            else:
                logging.error(f"❌ [TXN: {transaction_id}] Bank abort failed: {e.code()} - {e.details()}")
                return False, f"Bank abort failed: {e.details()}"
    



    
    def ProcessPayment(self, request, context):
        """Handles payment transactions using 2-Phase Commit protocol."""
        client_ip = context.peer()
        username = "Unknown"
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        if token:
            username = verify_jwt(token)  # Extract username from JWT

        if not username or username not in clients_db:
            logging.warning(f"❌ Unauthorized payment attempt by unknown user")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        transaction_id = request.transaction_id if request.transaction_id else str(uuid.uuid4())
        # logging.info(f"🔄 [TXN: {transaction_id}] {username} (IP: {client_ip}) initiated payment of ₹{request.amount} to {request.to_account}")
        
        sender_bank = request.sender_bank_name
        receiver_username = request.receiver_username
        receiver_bank = request.receiver_bank_name
        amount = request.amount

        if username == receiver_username and sender_bank == receiver_bank:
            logging.warning(f"❌ [TXN: {transaction_id}] {username} attempted self-transfer within the same bank.")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Cannot transfer money to your own account within the same bank.")


        logging.info(f"🔄 [TXN: {transaction_id}] {username} (IP: {client_ip}) initiated payment of ₹{amount} to {receiver_username} at {receiver_bank}")
        
        
        # Step 2: Check if the transaction has already been processed.
        # ✅ Check for duplicate transactions
        if transaction_id in transaction_states:
            logging.info(f"⚠️ [TXN: {transaction_id}] Duplicate transaction detected. Skipping processing.")
            context.abort(grpc.StatusCode.ALREADY_EXISTS, "Transaction already processed")
        
         # Initialize transaction state
        transaction_states[transaction_id] = {
        "status": "initiated",
        "sender_prepared": False,
        "receiver_prepared": False,
        "sender_committed": False,
        "receiver_committed": False,
        "sender_bank": sender_bank,
        "receiver_bank": receiver_bank,
        "sender_account": None,
        "receiver_account": None,
        "amount": amount,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "sender_username": username,
        "receiver_username": receiver_username,
    }

        save_transaction_state()  # ✅ Persist state    
        
        try:
           # ✅ **Retrieve sender's account based on selected bank**
            sender_details = clients_db.get(username, None)
            if not sender_details:
                logging.warning(f"❌ [TXN: {transaction_id}] {username} attempted payment, but account not found.")
                transaction_states[transaction_id]["status"] = "failed_sender_not_found"
                save_transaction_state()
                context.abort(grpc.StatusCode.NOT_FOUND, "User account not found")

            sender_accounts = sender_details["accounts"]
            sender_account = None
            for account in sender_accounts:
                if account["bank_name"] == sender_bank:
                    sender_account = account["account_number"]
                    break

            if not sender_account:
                logging.warning(f"❌ [TXN: {transaction_id}] {username} attempted payment from an unauthorized bank {sender_bank}.")
                transaction_states[transaction_id]["status"] = "failed_sender_invalid_bank"
                save_transaction_state()
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "Bank not linked to your account")

            transaction_states[transaction_id]["sender_account"] = sender_account  # ✅ Update sender account

            # ✅ **Verify sender's bank connection**
            if sender_bank not in bank_stubs:
                bank_stubs[sender_bank] = create_bank_stub(sender_bank)
                logging.info(f"✅ Secure connection established with sender's bank: {sender_bank}")

            sender_bank_stub = bank_stubs[sender_bank]
            # Check if sender has sufficient balance
            balance_response = sender_bank_stub.GetBalance(
                bank_pb2.BalanceRequest(account_number=sender_account)
            )
            
            if balance_response.balance < amount:
                transaction_states[transaction_id]["status"] = "failed_insufficient_funds"
                save_transaction_state()
                logging.warning(f"❌ [TXN: {transaction_id}] {username} attempted payment of ₹{amount} (Insufficient Funds)")
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Insufficient funds")
            
           
             # ✅ **Retrieve receiver's account number based on username & bank**
            receiver_details = clients_db.get(receiver_username, None)
            receiver_account = None
            if receiver_details:
                for account in receiver_details["accounts"]:
                    if account["bank_name"] == receiver_bank:
                        receiver_account = account["account_number"]
                        break

            if not receiver_account:
                logging.warning(f"❌ [TXN: {transaction_id}] {username} attempted payment to non-existent user {receiver_username} at {receiver_bank}")
                transaction_states[transaction_id]["status"] = "failed_receiver_not_found"
                save_transaction_state()
                context.abort(grpc.StatusCode.NOT_FOUND, "Receiver account not found")

            transaction_states[transaction_id]["receiver_account"] = receiver_account  # ✅ Update receiver account
    
            # Verify receiver's bank connection
            if receiver_bank not in bank_stubs:
                bank_stubs[receiver_bank] = create_bank_stub(receiver_bank)
                logging.info(f"✅ Secure connection established with receiver's bank: {receiver_bank}")
            
            receiver_bank_stub = bank_stubs[receiver_bank]
            
            #########################
            # PHASE 1: PREPARE PHASE
            #########################
            logging.info(f"🔄 [TXN: {transaction_id}] PREPARE PHASE started")
            
            # Ask sender bank to prepare (lock funds)
            sender_prepared, sender_message = self.prepare_transaction(
                transaction_id, sender_bank_stub, sender_account, amount, is_sender=True
            )
            
            transaction_states[transaction_id]["sender_prepared"] = sender_prepared
            
            if not sender_prepared:
                # If sender bank cannot prepare, abort the transaction
                transaction_states[transaction_id]["status"] = "aborted_sender_prepare_failed"
                save_transaction_state()
                logging.warning(f"❌ [TXN: {transaction_id}] Sender bank prepare failed: {sender_message}")
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message=f"Transaction aborted: {sender_message}"
                )
            
            logging.info(f"✅ [TXN: {transaction_id}] Sender bank prepared successfully")
            
            # Ask receiver bank to prepare
            receiver_prepared, receiver_message = self.prepare_transaction(
                transaction_id, receiver_bank_stub, receiver_account, amount, is_sender=False
            )
            
            transaction_states[transaction_id]["receiver_prepared"] = receiver_prepared
            
            if not receiver_prepared:
                # If receiver bank cannot prepare, abort both transactions
                transaction_states[transaction_id]["status"] = "aborted_receiver_prepare_failed"
                save_transaction_state()
                logging.warning(f"❌ [TXN: {transaction_id}] Receiver bank prepare failed: {receiver_message}")
                
                # Abort the sender transaction
                self.abort_transaction(
                    transaction_id, sender_bank_stub, sender_account, amount, is_sender=True
                )
                
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message=f"Transaction aborted: {receiver_message}"
                )
            
            logging.info(f"✅ [TXN: {transaction_id}] Receiver bank prepared successfully")
            logging.info(f"✅ [TXN: {transaction_id}] PREPARE PHASE completed successfully")
            
            #########################
            # PHASE 2: COMMIT PHASE
            #########################
            logging.info(f"🔄 [TXN: {transaction_id}] COMMIT PHASE started")
            
            # Commit the transaction at sender bank
            sender_committed, sender_commit_message = self.commit_transaction(
                transaction_id, sender_bank_stub, sender_account, amount, is_sender=True
            )
            
            transaction_states[transaction_id]["sender_committed"] = sender_committed
            
            if not sender_committed:
                # If sender commit fails, abort both transactions
                transaction_states[transaction_id]["status"] = "aborted_sender_commit_failed"
                save_transaction_state()
                logging.warning(f"❌ [TXN: {transaction_id}] Sender bank commit failed: {sender_commit_message}")
                
                # Abort both transactions
                self.abort_transaction(
                    transaction_id, sender_bank_stub, sender_account, amount, is_sender=True
                )
                self.abort_transaction(
                    transaction_id, receiver_bank_stub, receiver_account, amount, is_sender=False
                )
                
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message=f"Transaction aborted: {sender_commit_message}"
                )
            
            logging.info(f"✅ [TXN: {transaction_id}] Sender bank committed successfully")
            
            # Commit the transaction at receiver bank
            receiver_committed, receiver_commit_message = self.commit_transaction(
                transaction_id, receiver_bank_stub, receiver_account, amount, is_sender=False
            )
            
            transaction_states[transaction_id]["receiver_committed"] = receiver_committed
            
            if not receiver_committed:
                # If receiver commit fails, we have a serious problem - need to try recovery
                transaction_states[transaction_id]["status"] = "partial_commit_recovery_needed"
                save_transaction_state()
                logging.error(f"❌ [TXN: {transaction_id}] CRITICAL: Receiver bank commit failed but sender committed: {receiver_commit_message}")
                
                # Try to abort the receiver transaction (may not work if bank is down)
                self.abort_transaction(
                    transaction_id, receiver_bank_stub, receiver_account, amount, is_sender=False
                )
                
                # In a real system, we would need a recovery process here to ensure consistency
                # For simplicity, we'll return an error to the client
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message="Transaction partially completed - recovery process initiated"
                )
            
            # Both transactions committed successfully!
            transaction_states[transaction_id]["status"] = "completed"
            save_transaction_state()
            logging.info(f"✅ [TXN: {transaction_id}] Receiver bank committed successfully")
            logging.info(f"✅ [TXN: {transaction_id}] COMMIT PHASE completed successfully")
            logging.info(f"✅ [TXN: {transaction_id}] {username} sent ₹{amount} to {receiver_account} successfully")
            return payment_gateway_pb2.PaymentResponse(
                success=True, 
                message="Transaction successfully completed",
                transaction_id=transaction_id
            )
        
        except grpc.RpcError as e:
            # Handle gRPC errors
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                transaction_states[transaction_id]["status"] = "aborted_timeout"
                save_transaction_state()
                logging.error(f"❌ [TXN: {transaction_id}] Transaction timed out after {TRANSACTION_TIMEOUT}s")
                
                # Try to abort both transactions
                if transaction_states[transaction_id]["sender_bank"] and transaction_states[transaction_id]["sender_bank"] in bank_stubs:
                    self.abort_transaction(
                        transaction_id, 
                        bank_stubs[transaction_states[transaction_id]["sender_bank"]], 
                        transaction_states[transaction_id]["sender_account"], 
                        transaction_states[transaction_id]["amount"], 
                        is_sender=True
                    )
                
                if transaction_states[transaction_id]["receiver_bank"] and transaction_states[transaction_id]["receiver_bank"] in bank_stubs:
                    self.abort_transaction(
                        transaction_id, 
                        bank_stubs[transaction_states[transaction_id]["receiver_bank"]], 
                        transaction_states[transaction_id]["receiver_account"], 
                        transaction_states[transaction_id]["amount"], 
                        is_sender=False
                    )  
                
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message=f"Transaction aborted: Operation timed out after {TRANSACTION_TIMEOUT}s"
                )
            else:
                transaction_states[transaction_id]["status"] = "aborted_error"
                save_transaction_state()
                logging.error(f"❌ [TXN: {transaction_id}] Payment Failed: {e.code()} - {e.details()}")
                
                # Try to abort both transactions
                if transaction_states[transaction_id]["sender_bank"] and transaction_states[transaction_id]["sender_bank"] in bank_stubs:
                    self.abort_transaction(
                        transaction_id, 
                        bank_stubs[transaction_states[transaction_id]["sender_bank"]], 
                        transaction_states[transaction_id]["sender_account"], 
                        transaction_states[transaction_id]["amount"], 
                        is_sender=True
                    )
                
                if transaction_states[transaction_id]["receiver_bank"] and transaction_states[transaction_id]["receiver_bank"] in bank_stubs:
                    self.abort_transaction(
                        transaction_id, 
                        bank_stubs[transaction_states[transaction_id]["receiver_bank"]], 
                        transaction_states[transaction_id]["receiver_account"], 
                        transaction_states[transaction_id]["amount"], 
                        is_sender=False
                    )
                transaction_states[transaction_id]["status"] = "failed_error1"
                save_transaction_state()  
                
                return payment_gateway_pb2.PaymentResponse(
                    success=False, 
                    message=f"Transaction aborted: {e.details()}"
                )
        except Exception as ex:
            # Handle general exceptions
            transaction_states[transaction_id]["status"] = "aborted_exception"
            save_transaction_state()
            logging.error(f"❌ [TXN: {transaction_id}] Unexpected error: {str(ex)}")
            
            # Try to abort both transactions
            if transaction_states[transaction_id]["sender_bank"] and transaction_states[transaction_id]["sender_bank"] in bank_stubs:
                self.abort_transaction(
                    transaction_id, 
                    bank_stubs[transaction_states[transaction_id]["sender_bank"]], 
                    transaction_states[transaction_id]["sender_account"], 
                    transaction_states[transaction_id]["amount"], 
                    is_sender=True
                )
            
            if transaction_states[transaction_id]["receiver_bank"] and transaction_states[transaction_id]["receiver_bank"] in bank_stubs:
                self.abort_transaction(
                    transaction_id, 
                    bank_stubs[transaction_states[transaction_id]["receiver_bank"]], 
                    transaction_states[transaction_id]["receiver_account"], 
                    transaction_states[transaction_id]["amount"], 
                    is_sender=False
                )
                
            return payment_gateway_pb2.PaymentResponse(
                success=False, 
                message=f"Transaction aborted due to an unexpected error"
            )
    
    def CheckBalance(self, request, context):
        """Returns the client's account balance securely using JWT authentication."""
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        client_ip = context.peer()
        print("CheckBalance is called")
        username = verify_jwt(token) if token else None
       
        if not username or username not in clients_db:
            logging.warning(f"❌ [BALANCE CHECK] Unauthorized attempt from {client_ip}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")


        
        user_details = clients_db[username]
        sender_accounts = user_details["accounts"]  # ✅ Get all accounts
        bank_name = request.bank_name  # ✅ Get bank name from request

        # ✅ Step 1: Verify that the selected bank exists for the user
        sender_account = None
        for account in sender_accounts:
            if account["bank_name"] == bank_name:
                sender_account = account["account_number"]
                break

        if not sender_account:
            logging.warning(f"❌ [BALANCE CHECK] {username} attempted balance check from an unauthorized bank {bank_name}.")
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Bank not linked to your account")



        if bank_name not in BANK_PORTS:
            logging.warning(f"❌ [BALANCE CHECK] {username} attempted balance check (Failed: Bank {bank_name} not found)")
            context.abort(grpc.StatusCode.NOT_FOUND, "Bank not found")

        # ✅ Step 2: Ensure the selected bank is available
        if bank_name not in BANK_PORTS:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank {bank_name} not found)")
            context.abort(grpc.StatusCode.NOT_FOUND, "Bank not found")

        if bank_name not in bank_stubs:
            print("🔄 Calling create_bank_stub")
            bank_stubs[bank_name] = create_bank_stub(bank_name)
            logging.info(f"✅ Secure connection established with sender's bank: {bank_name}")

        # ✅ Step 3: Request balance from the correct bank
        try:
            response = bank_stubs[bank_name].GetBalance(
                bank_pb2.BalanceRequest(account_number=sender_account)
            )
            logging.info(f"✅ {username} from {client_ip} checked balance: ₹{response.balance}")
            return payment_gateway_pb2.BalanceResponse(balance=response.balance)
        except grpc.RpcError as e:
            logging.warning(f"❌ {username} attempted balance check (Failed: Bank service unavailable)")
            context.abort(grpc.StatusCode.UNAVAILABLE, "Bank service unavailable")



    def ViewTransactionHistory(self, request, context):
        """Returns all past transactions for an authenticated user."""
        print("ViewTransactionHistory is called")
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", None)
        username = verify_jwt(token) if token else None

        if not username or username not in clients_db:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        user_history = []

        # ✅ Fetch transactions where user is sender OR receiver
        for txn_id, txn_details in transaction_states.items():
            if txn_details.get("sender_username") == username:
                # Sender's view: Hide receiver's account number
                user_history.append({
                    "transaction_id": txn_id,
                    "from_bank": txn_details["sender_bank"],
                    "to_bank": txn_details["receiver_bank"],
                    "from_account_no": txn_details["sender_account"],
                    "to_user_id": txn_details["receiver_username"],
                    "amount": txn_details["amount"],
                    "timestamp": txn_details["timestamp"],
                    "status": txn_details["status"]
                })
            elif txn_details.get("receiver_username") == username:
                # Receiver's view: Hide sender's account number
                user_history.append({
                    "transaction_id": txn_id,
                    "from_bank": txn_details["sender_bank"],
                    "to_bank": txn_details["receiver_bank"],
                    "from_user_id": txn_details["sender_username"],
                    "amount": txn_details["amount"],
                    "timestamp": txn_details["timestamp"],
                    "status": txn_details["status"]
                })

        logging.info(f"✅ {username} viewed transaction history. {len(user_history)} records found.")
        return payment_gateway_pb2.TransactionHistoryResponse(transactions=user_history)

        

def serve():
    try:
         # Load server key and certificate
        with open('../certs/payment/payment.key', 'rb') as f:
            private_key = f.read()
        with open('../certs/payment/payment.crt', 'rb') as f:
            certificate_chain = f.read()
        with open('../certs/ca/ca.crt', 'rb') as f:
            root_certificates = f.read()
        
        # Create server credentials
        server_credentials = grpc.ssl_server_credentials(
            [(private_key, certificate_chain)],
            root_certificates=root_certificates,
            require_client_auth=True  # Require clients to authenticate (mutual TLS)
        )

        # Start Secure gRPC Server with interceptors for authorization and logging
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=[
                RegisterBankInterceptor(),  # Add this new interceptor first
                AuthorizationInterceptor(),
                LoggingInterceptor(),
                TransactionLoggingInterceptor()
            ]
        )
        
        # Try temporarily removing interceptors to see if they're causing the issue
        # server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        #   Add interceptors back one by one after confirming basic functionality
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