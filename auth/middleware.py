from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request
from auth.jwthandler import decode_access_token
from models.users import User as user_models
from core.database import SessionLocal
from fastapi.responses import RedirectResponse


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        print(path)
        # print('the path from auth middleware is')
        token = request.cookies.get("access_token")
        print("this is the   token  from the  middleware:" ,token)
        # Skip auth for login, signup, and docs
        public_paths = ["/users/login", "/users/signup", "/docs", "/openapi.json", "/static" , "/otp/getotp" , "/otp/verifyotp"]
        if any(path.startswith(p) for p in public_paths):
            return await call_next(request)
        token = request.cookies.get("access_token")
        user_id = None
        print("This is from middleware: ", token)
        if token:
            payload = decode_access_token(token)
            if payload:
                user_id = payload.get("sub")
        request.state.user_id = user_id
        if not user_id:
            return JSONResponse(status_code=401, content={"detail": "Please login to perform this action"})
        return await call_next(request)
