from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from core.database import Base, engine
from models.users import User
from models.projects import Project, ProjectDetail, ProjectHistory
from models.roles import Role 
from routers import users, project, roles 
from routers import otp
from auth.middleware import AuthMiddleware
# from utils import data
from models.otp import OTP

Base.metadata.create_all(bind=engine)

# data.seed_data()

app = FastAPI(title="Project Management API")

app.add_middleware(
CORSMiddleware,
allow_origins=["http://localhost:4200"],
allow_credentials=True,
allow_methods=["GET", "POST", "HEAD", "OPTIONS", "PATCH", "PUT", "DELETE"],
allow_headers=["Access-Control-Allow-Headers", 'Content-Type', 'Authorization', 'Access-Control-Allow-Origin'],
)



# app.add_middleware(AuthMiddleware)
# app.add_middleware(AuthMiddleware)
app.include_router(users.router)
app.include_router(project.router)
app.include_router(roles.router)
app.include_router(otp.router)





@app.get("/")
def read_root():
    return {"message": "FastAPI server is running"}
