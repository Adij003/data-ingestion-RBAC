from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from core.database import SessionLocal
from models import  roles as role_models , users as user_model
from schemas import  roles as roles_schemas
from sqlalchemy.exc import IntegrityError
from schemas import roles as roles_schemas
from auth.getCurrUser import get_current_user
from uuid import UUID ,uuid4
from fastapi import Query
from datetime import  datetime
from math import ceil

router = APIRouter(prefix="/roles", tags=["Roles"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/", response_model=roles_schemas.AllRoles)
def get_roles( request: Request,
    page: int = Query(1, ge=1),
    current_user: user_model.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    token = request.cookies.get("access_token")
    print("this is the  token  from  getrole:" , token)
    if not current_user:
        raise HTTPException(status_code=403 , detail="No  Login  User  Found")
    if not (current_user.is_admin or current_user.is_manager):
        raise HTTPException(status_code=403, detail="Only Admin or Manager can perform this action")

    limit = 10
    offset = (page - 1) * limit
    base_query = db.query(role_models.Role)
    total_count = base_query.count()
    total_pages = ceil(total_count / limit)
    roles = base_query.offset(offset).limit(limit).all()
    if not roles:
        raise HTTPException(status_code=404, detail="No roles found")

    return {
        "roles": roles,
        "pagination": {
            "total_count": total_count,
            "total_pages": total_pages,
            "current_page": page,
            "per_page": limit
        }
    }


@router.patch("/{role_id}", response_model=dict)
def update_role(
    role_id: UUID,
    role_data: roles_schemas.RoleData,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=403 , detail="No  Login  User  Found")
    if  not current_user.is_admin:
        raise HTTPException(status_code=403 , detail="Only   Admin  Can  Perform  this action")
    
    role = db.query(role_models.Role).filter(role_models.Role.role_id == role_id).first()

    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role_data.role_name:
        role.role_name = role_data.role_name
    if role_data.role_description is not None:
        role.role_description = role_data.role_description
    role.edited_by = f"{current_user.first_name} {current_user.last_name}"
    role.edited_on = datetime.utcnow()

    db.commit()
    db.refresh(role)
    return {
        "Status" : "success",
        "role" : role
    }


@router.post('/addRole', response_model=roles_schemas.RoleOut)
def add_new_role(
    payload: roles_schemas.CreateRole,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=403 , detail="No  Login  User  Found")
    if  not current_user.is_admin:
        raise HTTPException(status_code=403 , detail="Only   Admin or manager Can  Perform  this action")
    
    existing = db.query(role_models.Role).filter(role_models.Role.role_name == payload.role_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Role with this name already exists")

    new_role = role_models.Role(
        role_id=uuid4(),
        role_name=payload.role_name,
        role_description=payload.role_description or "",
        edited_by=f"{current_user.first_name} {current_user.last_name}",
        edited_on = datetime.utcnow()
    )

    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    return new_role

# @router.delete("/{role_id}")
# def deleteRole(role_id: UUID, db: Session = Depends(get_db)):
#     role = db.query(role_models.Role).filter(role_models.Role.role_id == role_id).first()
#     if not role:
#         raise HTTPException(status_code=404, detail="Role not found")
#     db.delete(role)
#     db.commit()
    
#     return {"detail": "Role deleted successfully"}



