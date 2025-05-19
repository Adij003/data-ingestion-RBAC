from pydantic import BaseModel , EmailStr
from typing import Optional, List
from schemas import projects
from uuid import UUID
from datetime import datetime

class UserCreate(BaseModel):
    emp_id: str
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    class Config():
        orm_mode = True

class UserData(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: UUID
    emp_id: str
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    is_active: bool
    is_manager: bool
    is_admin: bool

    class Config:
        from_attributes = True

class ManagerOut(BaseModel):
    id: UUID
    emp_id: str
    first_name: str
    last_name: str
    username: str  
    email: str
    is_admin: bool
    is_active: bool

    class Config:
        orm_mode = True


class LoginResponse(BaseModel):
    status:str
    user: UserOut
    projects: List[projects.ProjectDetailsOut]
    access_token: str
    token_type: str = "bearer" 

    class Config:
        orm_mode = True

class Managers(BaseModel):
    managers: List[ManagerOut]  

    class Config:
        orm_mode = True

class AllUsers(BaseModel):
    allusers: List[ManagerOut]  
    class Config:
        orm_mode = True

class ResteData(BaseModel):
    email:str
    password:str

    class Config():
        orm_mode = True



class AdminApprovalRequest(BaseModel):
    details_id: UUID
    admin_id: UUID
    admin_approved: str
    remark: Optional[str] = ""
   

class ProjectDetailResponse(BaseModel):
    details_id: UUID
    project_id: UUID
    employee_id: UUID
    role_id: UUID
    status: str
    manager_approved: bool
    admin_approved: str
    approved_manager: UUID | None
    last_edited_on: datetime | None
    last_edited_by: UUID | None

    class Config:
        orm_mode = True
