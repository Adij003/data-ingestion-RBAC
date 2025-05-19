from pydantic import BaseModel
from uuid import UUID
from typing import Optional, List
from datetime import datetime ,  date
class CreateRole(BaseModel):
    role_name: str
    role_description: Optional[str] = None

    class Config:
        orm_mode = True

class RoleOut(BaseModel):
    role_id: UUID
    role_name: str
    role_description: str
    edited_on:datetime
    edited_by:Optional[str] 
    class Config:
        orm_mode = True

class RoleData(BaseModel):
    role_name: Optional[str] = None
    role_description: Optional[str] = None
    class Config:
        orm_mode = True

class AllRoles(BaseModel):
    roles: List[RoleOut]
    pagination:dict
    class Config:
        orm_mode = True
