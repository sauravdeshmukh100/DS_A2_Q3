import grpc
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'protofiles')))





import grpc
import payment_gateway_pb2
import payment_gateway_pb2_grpc



# ✅ Global variable to store JWT token
jwt_token = None





def authenticate_client(stub, username, password):
    global jwt_token  # ✅ Ensure token is stored globally
    request = payment_gateway_pb2.AuthRequest(username=username, password=password)
    print("requst sent")
    response = stub.AuthenticateClient(request)
    print("response received")
    
    if response.authenticated:
        jwt_token = response.token  # ✅ Store globally
        print(f"✅ Login successful! Token: {jwt_token}")
    else:
        print("❌ Login failed! Invalid username or password.")





def check_balance(stub):
    if jwt_token is None:
        print("❌ Please authenticate first.")
        return
    
    metadata = [("authorization", jwt_token)]
    request = payment_gateway_pb2.BalanceRequest()
    response = None  # ✅ Initialize response to avoid "UnboundLocalError"

    try:
        response = stub.CheckBalance(request, metadata=metadata)  # ✅ Assign response inside try block
        print(f"💰 Your Balance: {response.balance}")
    except grpc.RpcError as e:
        print(f"❌ Error: {e.code()} - {e.details()} (Payment Gateway may be down)")

    if response is None:
        print("❌ Balance request failed. Please try again later.")





def process_payment(stub, to_account, amount):
    """Processes a payment using JWT authentication."""
    if jwt_token is None:
        print("❌ Please authenticate first.")
        return
    
    metadata = [("authorization", jwt_token)]  # ✅ Attach JWT token
    request = payment_gateway_pb2.PaymentRequest(to_account=to_account, amount=amount)
    
    try:
        response = stub.ProcessPayment(request, metadata=metadata)  # ✅ Send metadata
        print(f"📌 Payment Status: {response.message}")
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.FAILED_PRECONDITION:
            print("❌ Transaction failed: Insufficient funds.")
        else:
            print(f"❌ Payment failed: {e.code()} - {e.details()}")



def register_client(stub, username, password, bank_name, account_number):
    """Registers a new client."""
    request = payment_gateway_pb2.ClientRegistrationRequest(
        username=username, password=password, bank_name=bank_name, account_number=account_number
    )
    response = stub.RegisterClient(request)
    print(f"📌 Registration Status: {response.message}")

def main():
    with open("ca.crt", "rb") as f:
        trusted_certs = f.read()
    
    credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)

    with grpc.secure_channel("localhost:50052", credentials) as channel:  # ✅ Secure Connection
        stub = payment_gateway_pb2_grpc.PaymentGatewayStub(channel)

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
                authenticate_client(stub, username, password)

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












