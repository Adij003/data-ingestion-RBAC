from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models.otp import OTP
from sqlalchemy.orm import Session
from core.database import SessionLocal
from schemas.otp import OTPRequest, OTPResponse, OTPVerifyRequest, OTPVerifyResponse
from utils.generate_otp import generate_otp 
from  SendEmail import send_email
router = APIRouter(prefix="/otp", tags=["otp"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post('/getotp', response_model=OTPResponse)
def generate_opt(request: OTPRequest, db: Session = Depends(get_db)):
    otp_code = generate_otp()

    existing = db.query(OTP).filter_by(email=request.email).first()
    if existing:
        existing.otp = otp_code
    else:
        db.add(OTP(email=request.email, otp=otp_code))
    
    db.commit()

    # Send OTP email
    
    send_email(
        recipient_email=request.email,
        description=f"Hi {request.email},\n\nYour OTP for email confirmation is: {otp_code}\n\nThank you!\nTeam Ielektron"
    )

    return {
        "status": "success",
        "message": f"OTP sent to {request.email}"}



@router.post('/verifyotp', response_model=OTPVerifyResponse)
def verify_otp(request: OTPVerifyRequest, db: Session = Depends(get_db)):
    record = db.query(OTP).filter_by(email=request.email).first()

    if not record:
        raise HTTPException(status_code=404, detail="OTP not found for this email")

    if record.otp != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    return {"message": "OTP verified successfully"}
