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