# get user  from the  cookie
from fastapi import Request, Depends, HTTPException 
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from auth.jwthandler import decode_access_token
from  models.users  import User 
from core.database import SessionLocal
from jose import JWTError, ExpiredSignatureError
from jose import JWTError, ExpiredSignatureError

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        print("this is token from getCurrUser: ", token)
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token payload invalid")

        user = db.query(User).filter_by(id=user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user

    except ExpiredSignatureError:
        return RedirectResponse(url="/login", status_code=302)

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or malformed token")
