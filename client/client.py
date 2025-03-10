import grpc
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))





import grpc
import payment_gateway_pb2
import payment_gateway_pb2_grpc
import time
import logging

MAX_RETRIES = 3  # ✅ Define max retry attempts
RETRY_DELAY = 3  # ✅ Wait 3 seconds before retrying





# ✅ Global variable to store JWT token
jwt_token = None
stub = None  # ✅ Global stub for reuse





def authenticate_client(stub, username, password):
    """Authenticates a client using JWT and retries if the Payment Gateway is down."""
    global jwt_token  # ✅ Ensure token is stored globally
    
    request = payment_gateway_pb2.AuthRequest(username=username, password=password)
    print("🔄 Request sent")

    attempt = 0  # ✅ Track retry attempts
    while attempt < MAX_RETRIES:
        try:
            response = stub.AuthenticateClient(request)
            print("✅ Response received")

            if response.authenticated:
                print(f"✅ Login successful! Token: {response.token}")
                return True  # ✅ Exit on successful authentication
            else:
                
                if response.message == "Already logged in. Please log out first or wait for token expiration.":
                    
                    print("❌ Login failed! You are already logged in with an active session.")
                    return False  # ✅ Stop retrying on active session
                else:
                    print("❌ Login failed! Invalid username or password.")
                    return False  # ✅ Stop retrying on bad credentials

        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                attempt += 1
                print(f"❌ Payment Gateway is down. Retrying in {RETRY_DELAY} seconds... (Attempt {attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY)

                # ✅ Force reconnect by reinitializing stub securely
                print("🔄 Reconnecting to Payment Gateway...")
                initialize_stub()  # ✅ Uses secure connection instead of insecure_channel

                print("🔄 Retrying authentication...")
            elif e.code() == grpc.StatusCode.UNAUTHENTICATED:
                print("❌ Authentication failed: Invalid token or credentials.")
                return False  # ✅ Stop retrying on bad credentials
            elif e.code() == grpc.StatusCode.INVALID_ARGUMENT:
                print("❌ Authentication failed: Invalid request format.")
                return False
            else:
                print(f"❌ Authentication failed: {e.code()} - {e.details()}")
                return False  # ✅ Stop retrying on unexpected errors

    print("❌ Authentication failed after multiple attempts. Please check the server.")
    return False  # ✅ Authentication permanently failed





def check_balance(stub):
    """Checks balance with retries if Payment Gateway is down."""
    if jwt_token is None:
        print("❌ Please authenticate first.")
        return
    
    metadata = [("authorization", jwt_token)]
    request = payment_gateway_pb2.BalanceRequest()

    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            response = stub.CheckBalance(request, metadata=metadata)
            print(f"💰 Your Balance: {response.balance}")
            logging.info(f"✅ Balance check successful.")
            return  # ✅ Exit after successful balance check
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                attempt += 1
                logging.warning(f"🔄 Retrying balance check... Attempt {attempt}/{MAX_RETRIES}")
                print(f"🔄 Retrying balance check... Attempt {attempt}/{MAX_RETRIES}")
                time.sleep(RETRY_DELAY)  # ✅ Wait before retrying
                initialize_stub()  # ✅ Uses secure connection instead of insecure_channel

            else:
                print(f"❌ Balance check failed: {e.code()} - {e.details()}")
                logging.error(f"❌ Balance check failed: {e.code()} - {e.details()}")
                return  # ✅ Exit on non-network errors

    logging.error(f"❌ Balance check failed after {MAX_RETRIES} attempts.")
    print("❌ Balance check failed after multiple attempts. Please try again later.")





def process_payment(stub, to_account, amount):
    """Processes a payment using JWT authentication with retries."""
    if jwt_token is None:
        print("❌ Please authenticate first.")
        return
    
    metadata = [("authorization", jwt_token)]
    request = payment_gateway_pb2.PaymentRequest(to_account=to_account, amount=amount)

    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            response = stub.ProcessPayment(request, metadata=metadata)
            print(f"📌 Payment Status: {response.message}")
            logging.info(f"✅ Payment of ₹{amount} to {to_account} succeeded.")
            return  # ✅ Exit after successful payment
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                attempt += 1
                logging.warning(f"🔄 Retrying payment... Attempt {attempt}/{MAX_RETRIES}")
                print(f"🔄 Retrying payment... Attempt {attempt}/{MAX_RETRIES}")
                time.sleep(RETRY_DELAY)  # ✅ Wait before retrying
                initialize_stub()  # ✅ Uses secure connection instead of insecure_channel

            elif e.code() == grpc.StatusCode.FAILED_PRECONDITION:
                print("❌ Transaction failed: Insufficient funds.")
                logging.warning(f"❌ Payment of ₹{amount} to {to_account} failed due to insufficient funds.")
                return  # ✅ Exit if insufficient funds
            else:
                print(f"❌ Payment failed: {e.code()} - {e.details()}")
                logging.error(f"❌ Payment failed: {e.code()} - {e.details()}")
                return  # ✅ Exit on other errors

    logging.error(f"❌ Payment permanently failed after {MAX_RETRIES} attempts.")
    print("❌ Payment failed after multiple attempts. Please try again later.")



def register_client(stub, username, password, bank_name, account_number):
    """Registers a new client."""
    request = payment_gateway_pb2.ClientRegistrationRequest(
        username=username, password=password, bank_name=bank_name, account_number=account_number
    )
    response = stub.RegisterClient(request)
    print(f"📌 Registration Status: {response.message}")

def initialize_stub():
    """Creates a secure gRPC connection with TLS."""
    global stub  # ✅ Ensure stub persists across function calls

    with open("ca.crt", "rb") as f:
        trusted_certs = f.read()
    
    credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    channel = grpc.secure_channel("localhost:50052", credentials)  # ✅ Secure Connection

    stub = payment_gateway_pb2_grpc.PaymentGatewayStub(channel)
    print("🔄 Secure gRPC connection established.")

def main():
    initialize_stub()  # ✅ Initialize stub at startup
    while True:
        print("\nOptions:")
        print("1. Register Client")
        print("2. Authenticate")
        print("3. Process Payment")
        print("4. Check Balance")
        print("5. Exit")
        option = input("Select an option: ")

        if option == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            bank_name = input("Enter bank name: ")
            account_number = input("Enter account number: ")
            register_client(stub, username, password, bank_name, account_number)

        elif option == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            authenticate_client( stub , username, password)

        elif option == "3":
            to_account = input("Enter recipient account number: ")
            amount = float(input("Enter amount: "))
            process_payment(stub, to_account, amount)

        elif option == "4":
            check_balance(stub)

        elif option == "5":
            print("🚀 Exiting...")
            break

        else:
            print("❌ Invalid option. Please try again.")

if __name__ == "__main__":
    main()  # ✅ Now only one function handles everything












