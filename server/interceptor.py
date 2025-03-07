import grpc
import jwt
import logging
from datetime import datetime

# Logging setup
logging.basicConfig(filename="transactions.log", level=logging.INFO, format="%(asctime)s - %(message)s")

SECRET_KEY = "supersecretkey"

class AuthInterceptor(grpc.ServerInterceptor):
    """gRPC Interceptor for centralized authentication and logging."""

    def verify_jwt(self, token):
        """Verify the JWT token and extract username."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload["username"]
        except jwt.ExpiredSignatureError:
            return "EXPIRED"  # Token expired - match the value in payment_gateway.py
        except jwt.InvalidTokenError:
            return None  # Invalid token

    def intercept_service(self, continuation, handler_call_details):
        """Intercept gRPC calls to enforce authentication and log requests."""
        
        method = handler_call_details.method
        metadata = dict(handler_call_details.invocation_metadata)
        token = metadata.get("authorization", None)
        
        # Skip authentication for the AuthenticateClient method
        if method.endswith("/AuthenticateClient"):
            return continuation(handler_call_details)

        username = self.verify_jwt(token) if token else None
        
        # Create a handler that will abort with appropriate error
        def abort_with_error(error_code, error_message):
            def abort_handler(request, context):
                context.abort(error_code, error_message)
            return grpc.unary_unary_rpc_method_handler(abort_handler)
        
        if username == "EXPIRED":
            logging.warning(f"🔄 Token expired for {method}. User needs to refresh token.")
            return abort_with_error(grpc.StatusCode.UNAUTHENTICATED, "Token expired, please re-authenticate")
        elif not username:
            logging.warning(f"❌ Unauthorized access to {method} (Missing or Invalid Token)")
            return abort_with_error(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        logging.info(f"✅ {username} called {method}")
        return continuation(handler_call_details)