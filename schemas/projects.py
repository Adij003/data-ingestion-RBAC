from pydantic import BaseModel , EmailStr
from typing import Optional, List
from uuid import UUID
from datetime import date, datetime

from models.projects import ProjectStatusEnum , ProjectDetailsStatusEnum
from enum import Enum



class ProjectOut(BaseModel):
    project_id: UUID
    project_name: str
    project_description: Optional[str]
    project_owner: UUID
    manager_firstname: str
    manager_lastname: str
    project_status: str
    DA: bool
    AF: bool
    EA: bool
    DI: bool
    edited_by:str
    edited_on:datetime
    start_date: Optional[date]
    end_date: Optional[date]

    class Config:
        orm_mode = True

class ProjectOutManager(BaseModel):      
    project_id: UUID
    project_name: str
    project_description: Optional[str]
    project_owner: UUID
    project_status: str
    DA: bool
    AF: bool
    EA: bool
    DI: bool
    edited_by:str
    edited_on:datetime
    start_date: Optional[date]
    end_date: Optional[date]

    class Config:
        orm_mode = True


class ProjectDetailsOut(BaseModel):
    details_id: UUID
    project_id: UUID
    user_id: UUID
    project_name:str
    employee_id: str
    employee_firstname: str
    employee_lastname: str
    employee_email: EmailStr
    role_id: UUID
    role_name: str
    status: str
    manager_approved: bool
    approved_manager: UUID
    manager_name: str
    manager_email: EmailStr
    admin_approved: str 
    remark: Optional[str] = ""
    last_edited_on: datetime
    last_edited_by: UUID

    class Config:
        orm_mode = True

class  allProjectOut(BaseModel):
    allProjects:List[ProjectDetailsOut]
    pagination:dict
    class Config:
        orm_mode=True

class AllProjectsOut(BaseModel):
    projects: List[ProjectOut]
    pagination:dict
    class Config:
        orm_mode = True
class AllManagerProjects(BaseModel):
    projects:List[ProjectOutManager]
    class Config:
        orm_mode =True

class ProjectDetailUpdate(BaseModel):
    status: Optional[str]
    manager_approved: Optional[bool]
    approved_manager: Optional[UUID]
    admin_approved: Optional[str]
    role_id: Optional[UUID]
    employee_id: Optional[UUID]
    class Config:
        orm_mode = True

class AddNewUserToProjects(BaseModel):
    project_id: UUID
    employee_id: str
    user_id:UUID
    employee_firstname:str
    employee_lastname:str
    employee_email : EmailStr
    role_id: UUID
    status: Optional[str] = "ongoing"
    manager_approved: bool 
    approved_manager: UUID
    admin_approved: str
    class Config:
        orm_mode = True

class AddNewProjects(BaseModel):
    project_name: str
    project_description: Optional[str]
    project_owner: UUID
    project_status:Optional[str] = "ongoing"
    start_date: Optional[date]
    end_date: Optional[date]
    DA: bool
    AF: bool
    EA: bool
    DI: bool
    class Config:
        orm_mode = True
class AddProjectResponse(BaseModel):
    message:str


class ProjectUpdate(BaseModel):
    project_name:        Optional[str] = None
    project_description: Optional[str] = None
    project_status:      Optional[str] = None
    project_owner:       Optional[UUID] = None
    start_date:          Optional[date] = None
    end_date :           Optional[date] = None
    DA:            Optional[bool] = False
    AF:            Optional[bool] = False
    EA:            Optional[bool] = False
    DI:            Optional[bool] = False
    class Config:
        orm_mode = True