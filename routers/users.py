from fastapi import APIRouter, Depends, HTTPException, status ,Request , Response, Query
from sqlalchemy.orm import Session
from core.database import SessionLocal
from models import users as user_models, projects 
from models.roles import Role
from schemas import users as user_schemas , projects as project_scjemas , otp as otp_schemas
import hashlib
from auth.jwthandler import create_access_token
from datetime import timedelta
from uuid import UUID
import uuid
from datetime import datetime
from SendEmail import send_email
from utils.hash import hash_password , verify_password
import random
from math import ceil
from auth.getCurrUser import get_current_user
from sqlalchemy import asc , desc
from utils.email_templates import manager_request_user_assignment_template , html_description_manager ,user_account_created_template,  html_description_user , html_description_otp
from utils.searchCode import search_model_any_keyword
router = APIRouter(prefix="/users", tags=["Users"])
from sqlalchemy.orm import aliased
from sqlalchemy import or_, func, desc , and_
from math import ceil

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post('/logout' , response_model=dict)
def logout(response : Response):
    response.delete_cookie("access_token")
    return {"message" :"Logged Out"}


@router.post("/signup", response_model=dict)
def signup(user_data: user_schemas.UserCreate, response:Response , db: Session = Depends(get_db)):
    existing_user = db.query(user_models.User).filter((user_models.User.email == user_data.email) | (user_models.User.emp_id == user_data.emp_id)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user_data.password)

    new_user = user_models.User(
        id=uuid.uuid4(),
        emp_id=user_data.emp_id,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        username=f"{user_data.first_name[0]}{user_data.last_name[0]}",
        email=user_data.email,
        password=hashed_password,
        is_active=True,
        is_manager=False,
        is_admin=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Set Cookies Part
    access_token = create_access_token(data={"sub": str(new_user.id)})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Set to True in production (HTTPS only)
        samesite="lax",
        path="/"
    )

    #Email Sending  Part
    user_name =  user_data.first_name + user_data.last_name
    descritpion_user= user_account_created_template(name=user_name)
    send_email(recipient_email=user_data.email  , description=descritpion_user)
    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_schemas.UserOut.from_orm(new_user)
    }

@router.post("/login", response_model=user_schemas.LoginResponse)
def login_user(email: str, password: str, response: Response, db: Session = Depends(get_db)):
    user_obj = db.query(user_models.User).filter_by(email=email).first()

    if not user_obj or not verify_password(password, user_obj.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    access_token = create_access_token(
        data={"sub": str(user_obj.id)},
        expires_delta=timedelta(minutes=60)
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Set to True in production
        samesite="lax",
        path="/",
    )

    project_details = db.query(projects.ProjectDetail).filter_by(employee_id=user_obj.id).all()

    # Convert each project to a dictionary
    project_dicts = [p.__dict__ for p in project_details]
    for project in project_dicts:
        project.pop("_sa_instance_state", None)  # Remove SQLAlchemy internal field

    return {
        "status": "success",
        "user": user_schemas.UserOut.from_orm(user_obj),
        "projects": project_dicts,
        "access_token": access_token,
        "token_type": "bearer"
    }



@router.get('/getAllUsers', response_model=user_schemas.AllUsers)
def getusers(db: Session = Depends(get_db)):
    allUsers_obj = db.query(user_models.User).filter(
        (user_models.User.is_manager == False) & 
        (user_models.User.is_admin == False)
    ).all()
    


    if not allUsers_obj:
        raise HTTPException(status_code=404, detail="No users found")
    
    return {"allusers": allUsers_obj}


@router.get("/manager", response_model=user_schemas.Managers)
def get_managers(
    current_user: user_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=403 , detail="no logged in  user  found . Please  login  to  perform  this   action")
    manage_obj = db.query(user_models.User).filter_by(is_manager=True).all()
    if not manage_obj:
        raise HTTPException(status_code=404, detail="No managers found")

    return {"managers": manage_obj}

@router.put("/update-user/{user_id}", response_model=user_schemas.UserOut)
def update_user(user_id: UUID, user_data: user_schemas.UserOut, db: Session = Depends(get_db)):
    user_obj = db.query(user_models.User).filter_by(id=user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    for attr, value in user_data.dict(exclude_unset=True).items():
        setattr(user_obj, attr, value)
    
    db.commit()
    db.refresh(user_obj)
    return user_obj


@router.put("/delete-user/{user_id}")
def deactivate_user(user_id: UUID, db: Session = Depends(get_db)):
    user_obj = db.query(user_models.User).filter_by(id=user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    user_obj.is_active = False
    db.commit()
    return {"detail": "User deactivated successfully"}

@router.post("/reset-password")
def reset_user_password(email:str, newpassword:str, db:Session =  Depends(get_db)):
    user_obj = db.query(user_models.User).filter(user_models.User.email == email).first()

    if not  user_obj:
        raise HTTPException(status_code=404, detail="User not found")
    hashed_password = hash_password(newpassword)
    user_obj.password = hashed_password
    # user_obj.password = newpassword
    db.commit()
    db.refresh(user_obj)
    return {"detail":"user password   has  changed  successfully"}

from math import ceil
from fastapi import Query

@router.get("/Approved/new-user-request/{user_id}", response_model=project_scjemas.allProjectOut)
def get_Approved_users(
    request: Request,
    user_id: UUID,
    page: int = Query(1, ge=1),
     search: str = Query("", alias="search"),
    current_user: user_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    token = request.cookies.get("access_token")
    print("this is the token from get not approved users:", token)
    print("search  query is : " , search)
    if not current_user:
        raise HTTPException(status_code=403, detail="No Login User Found")
    if not (current_user.is_admin or current_user.is_manager):
        raise HTTPException(status_code=403, detail="Only Admin or Manager Can Perform This Action")

    user = db.query(user_models.User).filter(user_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found")

    limit = 10
    offset = (page - 1) * limit

    ApprovedManager = aliased(user_models.User)

    base_query = db.query(projects.ProjectDetail,
                          projects.Project,
                          user_models.User, 
                          Role,
                          ApprovedManager
                         ).join(projects.Project, projects.ProjectDetail.project_id == projects.Project.project_id
                         ).join(user_models.User, projects.ProjectDetail.employee_id == user_models.User.id
                         ).join(Role, projects.ProjectDetail.role_id == Role.role_id
                         ).join(ApprovedManager, projects.ProjectDetail.approved_manager == ApprovedManager.id, isouter=True
                         ).filter(
                             projects.ProjectDetail.manager_approved == True,
                             projects.ProjectDetail.admin_approved.in_(["Pending", "Rejected"])
                         ).order_by(desc(projects.ProjectDetail.last_edited_on))
    
    if user.is_manager:
        base_query = base_query.filter(projects.ProjectDetail.approved_manager == user_id)

    if search:
        keywords = search.lower().split()
        search_filters = []
        for keyword in keywords:
            term = f"%{keyword}%"
            search_filters.append(or_(
                func.lower(projects.ProjectDetail.admin_approved).like(term),
                func.lower(projects.ProjectDetail.remark).like(term),
                func.lower(projects.ProjectDetail.status).like(term),
                func.lower(projects.Project.project_name).like(term),
                func.lower(user_models.User.first_name).like(term),
                func.lower(user_models.User.last_name).like(term),
                func.lower(user_models.User.email).like(term),
                func.lower(Role.role_name).like(term),
                func.lower(ApprovedManager.first_name).like(term),
                func.lower(ApprovedManager.last_name).like(term),
                func.lower(ApprovedManager.email).like(term),
            ))
        base_query = base_query.filter(*search_filters)

    total_count = base_query.distinct().count()
    total_pages = ceil(total_count / limit)

    results = base_query.offset(offset).limit(limit).all()

    allProjectsout = []
    for projDetail, projData, empUser, roleData, apprManager in results:
        outOneProject = {
            "details_id": projDetail.details_id,
            "project_id": projDetail.project_id,
            "project_name": projData.project_name if projData else None,
            "user_id": empUser.id,
            "employee_id": empUser.emp_id,
            "employee_firstname": empUser.first_name,
            "employee_lastname": empUser.last_name,
            "employee_email": empUser.email,
            "role_id": roleData.role_id,
            "role_name": roleData.role_name,
            "status": projDetail.status,
            "manager_approved": projDetail.manager_approved,
            "approved_manager": projDetail.approved_manager,
            "manager_name": f"{apprManager.first_name if apprManager else ''} {apprManager.last_name if apprManager else ''}".strip(),
            "manager_email": apprManager.email if apprManager else None,
            "admin_approved": projDetail.admin_approved,
            "remark": projDetail.remark,
            "last_edited_on": projDetail.last_edited_on,
            "last_edited_by": projDetail.last_edited_by,
            "request_project": projDetail.project_request_date,
            "approved_project": projDetail.project_Approve_date
        }
        allProjectsout.append(outOneProject)

    return {
        "allProjects": allProjectsout,
        "pagination": {
            "total_count": total_count,
            "total_pages": total_pages,
            "current_page": page,
            "per_page": limit
        }
    }




@router.get("/notApproved/new-user-request/{user_id}", response_model=project_scjemas.allProjectOut)
def get_notApproved_users(
    request: Request,
    user_id: UUID,
    current_user: user_models.User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    search: str = Query("", alias="search"),
    db: Session = Depends(get_db)
):
    token = request.cookies.get("access_token")
    print("this is the token from get not approved users:", token)
    print("search  query is : " , search)
    if not current_user:
        raise HTTPException(status_code=403, detail="No Login User Found")
    if not (current_user.is_admin or current_user.is_manager):
        raise HTTPException(status_code=403, detail="Only Admin or Manager Can Perform This Action")

    user = db.query(user_models.User).filter(user_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found")

    limit = 10
    offset = (page - 1) * limit

    ApprovedManager = aliased(user_models.User)

    base_query = db.query(projects.ProjectDetail,
                          projects.Project,
                          user_models.User, 
                          Role,
                          ApprovedManager
                         ).join(projects.Project, projects.ProjectDetail.project_id == projects.Project.project_id
                         ).join(user_models.User, projects.ProjectDetail.employee_id == user_models.User.id
                         ).join(Role, projects.ProjectDetail.role_id == Role.role_id
                         ).join(ApprovedManager, projects.ProjectDetail.approved_manager == ApprovedManager.id, isouter=True
                         ).filter(
                             projects.ProjectDetail.manager_approved == True,
                             projects.ProjectDetail.admin_approved.in_(["Pending", "Rejected"])
                         ).order_by(desc(projects.ProjectDetail.last_edited_on))
    
    if user.is_manager:
        base_query = base_query.filter(projects.ProjectDetail.approved_manager == user_id)

    if search:
        keywords = search.lower().split()
        search_filters = []
        for keyword in keywords:
            term = f"%{keyword}%"
            search_filters.append(or_(
                func.lower(projects.ProjectDetail.admin_approved).like(term),
                func.lower(projects.ProjectDetail.remark).like(term),
                func.lower(projects.ProjectDetail.status).like(term),
                func.lower(projects.Project.project_name).like(term),
                func.lower(user_models.User.first_name).like(term),
                func.lower(user_models.User.last_name).like(term),
                func.lower(user_models.User.email).like(term),
                func.lower(Role.role_name).like(term),
                func.lower(ApprovedManager.first_name).like(term),
                func.lower(ApprovedManager.last_name).like(term),
                func.lower(ApprovedManager.email).like(term),
            ))
        base_query = base_query.filter(*search_filters)

    total_count = base_query.distinct().count()
    total_pages = ceil(total_count / limit)

    results = base_query.offset(offset).limit(limit).all()

    allProjectsout = []
    for projDetail, projData, empUser, roleData, apprManager in results:
        outOneProject = {
            "details_id": projDetail.details_id,
            "project_id": projDetail.project_id,
            "project_name": projData.project_name if projData else None,
            "user_id": empUser.id,
            "employee_id": empUser.emp_id,
            "employee_firstname": empUser.first_name,
            "employee_lastname": empUser.last_name,
            "employee_email": empUser.email,
            "role_id": roleData.role_id,
            "role_name": roleData.role_name,
            "status": projDetail.status,
            "manager_approved": projDetail.manager_approved,
            "approved_manager": projDetail.approved_manager,
            "manager_name": f"{apprManager.first_name if apprManager else ''} {apprManager.last_name if apprManager else ''}".strip(),
            "manager_email": apprManager.email if apprManager else None,
            "admin_approved": projDetail.admin_approved,
            "remark": projDetail.remark,
            "last_edited_on": projDetail.last_edited_on,
            "last_edited_by": projDetail.last_edited_by,
            "request_project": projDetail.project_request_date,
            "approved_project": projDetail.project_Approve_date
        }
        allProjectsout.append(outOneProject)

    return {
        "allProjects": allProjectsout,
        "pagination": {
            "total_count": total_count,
            "total_pages": total_pages,
            "current_page": page,
            "per_page": limit
        }
    }


@router.patch("/admin/approve-user")
def approve_user_by_admin(
    data: user_schemas.AdminApprovalRequest,
    db: Session = Depends(get_db)
    , current_user: user_models.User = Depends(get_current_user)
):
    
    if not current_user:
        raise HTTPException(status_code=403 , detail="No  Login  User  Found")
    if  not current_user.is_admin:
        raise HTTPException(status_code=403 , detail="Only   Admin Can  Perform  this action")
    
    admin_user = db.query(user_models.User).filter(user_models.User.id == data.admin_id).first()
    if not admin_user:
        raise HTTPException(status_code=404, detail="Admin user not found")

    if not admin_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can perform this action")

    detail = db.query(projects.ProjectDetail).filter(projects.ProjectDetail.details_id == data.details_id).first()
    if not detail:
        raise HTTPException(status_code=404, detail="Project detail not found")

    if not detail.manager_approved:
        raise HTTPException(status_code=400, detail="Project must be approved by manager first")

    currProject = db.query(projects.Project).filter(projects.Project.project_id == detail.project_id).first()
    if not currProject:
        raise HTTPException(status_code=404, detail="Project not found")

    manager = db.query(user_models.User).filter(user_models.User.id == detail.approved_manager).first()
    if not manager:
        raise HTTPException(status_code=404, detail="Manager not found")

    employee = db.query(user_models.User).filter(user_models.User.id == detail.employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    detail.admin_approved = data.admin_approved
    detail.remark = data.remark
    detail.last_edited_on = datetime.utcnow()
    detail.last_edited_by = data.admin_id
    detail.project_Approve_date = datetime.utcnow()
    db.commit()

    if data.admin_approved == 'Approved':

        manager_email_html = html_description_manager(
            project=currProject,
            manager=f"{manager.first_name} {manager.last_name}",
            admin=f"{admin_user.first_name} {admin_user.last_name}"
        )
        send_email(
            recipient_email=manager.email,
            description=manager_email_html
        )


        user_email_html = html_description_user(
            admin=f"{admin_user.first_name} {admin_user.last_name}",
            user=f"{employee.first_name} {employee.last_name}",
            project=currProject,
            manager=f"{manager.first_name} {manager.last_name}"
        )
        send_email(
            recipient_email=employee.email,
            description=user_email_html
        )

        return {"detail": "User has been approved by admin"}
    
    else:
        rejection_message = f"""
        <h2 style="color: #dc3545;">❌ Project Assignment Rejected</h2>
        <p>Dear {manager.first_name} {manager.last_name},</p>

        <p>Your request to assign <strong>{employee.first_name} {employee.last_name}</strong> to the project <strong>{currProject.project_name}</strong> has been <strong>rejected by {admin_user.first_name} {admin_user.last_name}</strong>.</p>

        <p><strong>Remark:</strong> {data.remark}</p>

        <p style="margin-top: 30px;">Regards,<br>C2DeVal Admin</p>
        """
        send_email(
            recipient_email=manager.email,
            description=rejection_message
        )

        return {"detail": "Admin rejected the user/project", "remark": data.remark}
