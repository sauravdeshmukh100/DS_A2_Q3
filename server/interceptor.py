import logging
import grpc

# Configure logging
logging.basicConfig(filename="transactions.log", level=logging.INFO, format="%(asctime)s - %(message)s")

class LoggingInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        client_ip = handler_call_details.invocation_metadata[0].value if handler_call_details.invocation_metadata else "Unknown"
        
        logging.info(f"✅ Request from {client_ip} - Method: {method}")
        
        try:
            response = continuation(handler_call_details)
            logging.info(f"✅ Success: {method}")
            return response
        except grpc.RpcError as e:
            logging.error(f"❌ Error in {method}: {e.code()} - {e.details()}")
            raise e

# Add logging for transactions
class TransactionLoggingInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        
        if "ProcessPayment" in method:
            try:
                response = continuation(handler_call_details)
                logging.info(f"✅ Transaction processed successfully in {method}")
                return response
            except grpc.RpcError as e:
                if e.code() == grpc.StatusCode.UNAVAILABLE:
                    logging.warning(f"🔄 Retrying {method} due to network failure")
                logging.error(f"❌ Transaction failed in {method}: {e.code()} - {e.details()}")
                raise e
        else:
            return continuation(handler_call_details)
