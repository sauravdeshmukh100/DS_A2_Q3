# import payment_gateway_pb2
# import payment_gateway_pb2_grpc


# # Global variable to store JWT token after login
# jwt_token = None

# def authenticate_client(stub):
#     username = input("Enter username: ")
#     password = input("Enter password: ")
#     """Logs in the user and stores the JWT token."""
#     global jwt_token
#     request = payment_gateway_pb2.AuthRequest(username=username, password=password)
#     response = stub.AuthenticateClient(request)
    
#     if response.authenticated:
#         print(f"✅ Login successful! Token: {response.token}")
#         jwt_token = response.token  # Store the JWT token
#     else:
#         print("❌ Login failed! Invalid username or password.")



# # def authenticate_client(stub):
# #     username = input("Enter username: ")
# #     password = input("Enter password: ")

# #     request = payment_gateway_pb2.AuthRequest(username=username, password=password)
# #     response = stub.AuthenticateClient(request)

# #     if response.authenticated:
# #         print("Authentication successful!")
# #         return response.token
# #     else:
# #         print("Authentication failed!")
# #         return None


# def register_client(stub):
#     username = input("Enter username: ")
#     password = input("Enter password: ")
#     bank_name = input("Enter bank name: ")
#     account_number = input("Enter account number: ")

#     request = payment_gateway_pb2.ClientRegistrationRequest(
#         username=username,
#         password=password,
#         bank_name=bank_name,
#         account_number=account_number
#     )

#     response = stub.RegisterClient(request)
#     print(f"Registration Response: {response.message}")



# def process_payment(stub, token):
#     from_account = input("Enter your account number: ")
#     to_account = input("Enter recipient's account number: ")
#     bank_name = input("Enter recipient's bank name: ")
#     amount = float(input("Enter amount to send: "))

#     request = payment_gateway_pb2.PaymentRequest(
#         token=token,
#         from_account=from_account,
#         to_account=to_account,
#         bank_name=bank_name,
#         amount=amount
#     )

#     response = stub.ProcessPayment(request)
#     print(f"Payment Status: {response.message}")

# def process_payment(stub):
#     to_account = input("Enter recipient's account number: ")
#     #bank_name = input("Enter recipient's bank name: ")
#     amount = float(input("Enter amount to send: "))
#     """Processes a payment using JWT authentication."""
#     if not jwt_token:
#         print("❌ You need to log in first!")
#         return
    
#     request = payment_gateway_pb2.PaymentRequest(token=jwt_token, to_account=to_account, amount=amount)
#     response = stub.ProcessPayment(request)
#     print(f"📌 Payment Status: {response.message}")    


# def check_balance(stub):
#     """Requests balance using JWT authentication."""
#     if not jwt_token:
#         print("❌ You need to log in first!")
#         return
    
#     request = payment_gateway_pb2.BalanceRequest(token=jwt_token)
#     response = stub.CheckBalance(request)
#     if response.balance == -1:
#         print("❌ Unauthorized request! Token may be invalid or expired.")
#     else:
#         print(f"💰 Your Balance: {response.balance}")


# # def check_balance(stub, token):
# #     account_number = input("Enter your account number: ")

# #     request = payment_gateway_pb2.BalanceRequest(
# #         token=token,
# #         account_number=account_number
# #     )

# #     response = stub.CheckBalance(request)
# #     if response.balance >= 0:
# #         print(f"Your account balance is: Rs. {response.balance}")
# #     else:
# #         print("Unauthorized request!")

# def main():
#     channel = grpc.insecure_channel("localhost:50052")
#     stub = payment_gateway_pb2_grpc.PaymentGatewayStub(channel)

#     token = None

#     while True:
#         print("\nOptions:")
#         print("1. Register Client")
#         print("2. Authenticate")
#         print("3. Process Payment")
#         print("4. Check Balance")
#         print("5. Exit")

#         choice = input("Select an option: ")

#         if choice == "1":
#             register_client(stub)
#         elif choice == "2":
#             token = authenticate_client(stub)
#         elif choice == "3":
#             if token:
#                 process_payment(stub, token)
#             else:
#                 print("Please authenticate first.")
#         elif choice == "4":
#             if token:
#                 check_balance(stub, token)
#             else:
#                 print("Please authenticate first.")
#         elif choice == "5":
#             break
#         else:
#             print("Invalid choice. Please try again.")

# if __name__ == "__main__":
#     main()



# def authenticate_client(stub, username, password):
#     """Logs in the user and stores the JWT token."""
#     global jwt_token  # ✅ Ensure we modify the global variable
#     request = payment_gateway_pb2.AuthRequest(username=username, password=password)
#     # metadata = [("authorization", jwt_token)]
#     response = stub.AuthenticateClient(request)
    
#     if response.authenticated:
#         jwt_token = response.token  # ✅ Store JWT token globally
#         print(f"✅ Login successful! Token: {jwt_token}")
#     else:
#         print("❌ Login failed! Invalid username or password.")



# def check_balance(stub):
#     """Requests balance using JWT authentication."""
#     if jwt_token is None:
#         print("❌ Please authenticate first.")
#         return
    
#     metadata = [("authorization", jwt_token)]  # ✅ Attach JWT token
#     request = payment_gateway_pb2.BalanceRequest()
    
#     try:
#         response = stub.CheckBalance(request, metadata=metadata)  # ✅ Send metadata
#         if response.balance == -1:
#             print("❌ Unauthorized request! Token may be invalid or expired.")
#             print("🔄 Re-authenticating...")
#             username = input("Enter username: ")
#             password = input("Enter password: ")
#             authenticate_client(stub, username, password)  # ✅ Refresh token and retry
#     except grpc.RpcError as e:
#         print(f"❌ Error: {e.code()} - {e.details()} (Payment Gateway may be down)")

#     print(f"💰 Your Balance: {response.balance}")


# def check_balance(stub):
#     """Requests balance using JWT authentication."""
#     if jwt_token is None:
#         print("❌ Please authenticate first.")
#         return
    
#     metadata = [("authorization", jwt_token)]
#     request = payment_gateway_pb2.BalanceRequest()
    
#     try:
#         response = stub.CheckBalance(request, metadata=metadata)
#         if response.balance == -1:
#             if response.message == "EXPIRED":
#                 print("🔄 Token expired! Re-authenticating automatically...")
#                 username = input("Enter username: ")
#                 password = input("Enter password: ")
#                 authenticate_client(stub, username, password)  # ✅ Refresh token automatically
#                 return check_balance(stub)  # ✅ Retry request with new token
#     except grpc.RpcError as e:
#         print(f"❌ Error: {e.code()} - {e.details()} (Payment Gateway may be down)")

#     print(f"💰 Your Balance: {response.balance}")

