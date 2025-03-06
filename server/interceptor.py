import grpc
import jwt
import logging
from datetime import datetime

# Logging setup
logging.basicConfig(filename="transactions.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Secret key for JWT validation
SECRET_KEY = "supersecretkey"


class AuthInterceptor(grpc.ServerInterceptor):
    """gRPC Interceptor for centralized authentication and logging."""

    def verify_jwt(self, token):
        """Verify the JWT token and extract username."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload["username"]
        except jwt.ExpiredSignatureError:
            return None  # Token expired
        except jwt.InvalidTokenError:
            return None  # Invalid token

    def intercept_service(self, continuation, handler_call_details):
        """Intercept gRPC calls to enforce authentication and log requests."""

        method = handler_call_details.method
        
        # ✅ Allow `AuthenticateClient` request without a token
        if "AuthenticateClient" in method:
            return continuation(handler_call_details)

        # ✅ Extract JWT token from metadata
        metadata = dict(handler_call_details.invocation_metadata)
        token = metadata.get("authorization", None)

        username = self.verify_jwt(token) if token else None
        if not username:
            logging.warning(f"❌ Unauthorized access to {method} (Missing or Invalid Token)")
            def abort_function(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")
            return grpc.unary_unary_rpc_method_handler(abort_function)

        logging.info(f"✅ {username} called {method}")
        return continuation(handler_call_details)


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
#         method = handler_call_details.method
#         metadata = dict(handler_call_details.invocation_metadata)
#         token = metadata.get("authorization", None)

#         username = self.verify_jwt(token) if token else None
#         if not username:
#             logging.warning(f"❌ Unauthorized access to {method} (Missing or Invalid Token)")
#             return grpc.unary_unary_rpc_method_handler(lambda req, ctx: ctx.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token"))

#         logging.info(f"✅ {username} called {method}")
#         return continuation(handler_call_details)
    



    # def intercept_service(self, continuation, handler_call_details):
    #     """Intercept gRPC calls to enforce authentication and log requests."""
        
    #     # ✅ Extract method name
    #     method = handler_call_details.method
        
    #     # ✅ Extract metadata (where token is sent)
    #     metadata = dict(handler_call_details.invocation_metadata)
    #     token = metadata.get("authorization", None)
        
    #     # ✅ Authenticate request
    #     username = self.verify_jwt(token) if token else None
    #     if not username:
    #         logging.warning(f"❌ Unauthorized access to {method} (Missing or Invalid Token)")
    #         context = grpc.ServicerContext()
    #         context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")
        
    #     # ✅ Log request
    #     logging.info(f"✅ {username} called {method}")

    #     # ✅ Process the actual request
    #     return continuation(handler_call_details)

