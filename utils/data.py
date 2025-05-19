from sqlalchemy.orm import Session
from core.database import engine, Base
from models.users import User
from models.roles import Role
from models.projects import Project, ProjectDetail, ProjectHistory
import uuid
import random
from datetime import date, timedelta, datetime
import enum

class ProjectStatusEnum(str, enum.Enum):
    IN_PROGRESS = "Ongoing"
    COMPLETED = "Completed"
    ON_HOLD = "On Hold"
    DROPPED = "Dropped"

class ProjectDetailsStatusEnum(str, enum.Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"


def random_date(start, end):
    return start + timedelta(days=random.randint(0, (end - start).days))

def seed_data():
    with Session(engine) as session:
        # --- Create users ---
        user_list = []

        # Admin who is also a manager
        admin_manager = User(
            id=uuid.uuid4(),
            emp_id="EMP001",
            first_name="AdminManager",
            last_name="User",
            username="admin_manager",
            email="admin_manager@example.com",
            password="adminpass",  # Replace with hashed password
            is_manager=True,
            is_admin=True,
            is_active=True
        )
        session.add(admin_manager)
        user_list.append(admin_manager)

        # Two managers (not admin)
        for i in range(2, 4):
            manager = User(
                id=uuid.uuid4(),
                emp_id=f"EMP{str(i).zfill(3)}",
                first_name=f"Manager{i}",
                last_name="User",
                username=f"manager{i}",
                email=f"manager{i}@example.com",
                password=f"managerpass{i}",
                is_manager=True,
                is_admin=False,
                is_active=True
            )
            session.add(manager)
            user_list.append(manager)

        # Seven regular employees
        for i in range(4, 11):
            employee = User(
                id=uuid.uuid4(),
                emp_id=f"EMP{str(i).zfill(3)}",
                first_name=f"Emp{i}",
                last_name="User",
                username=f"user{i}",
                email=f"user{i}@example.com",
                password=f"pass{i}",
                is_manager=False,
                is_admin=False,
                is_active=True
            )
            session.add(employee)
            user_list.append(employee)

        session.commit()

        # --- Create roles ---
        role_list = []
        for i in range(5):
            role = Role(
                role_id=uuid.uuid4(),
                role_name=f"Role{i}",
                role_description=f"Description for Role{i}",
                edited_by="user1"
            )
            session.add(role)
            role_list.append(role)
        session.commit()

        # --- Create projects ---
        project_list = []
        for i in range(5):
            editor = random.choice(user_list)
            project = Project(
                project_id=uuid.uuid4(),
                project_name=f"Project {i}",
                project_description=f"Description {i}",
                project_owner=random.choice(user_list).id,
                project_status=random.choice(list(ProjectStatusEnum)).value,
                DA=bool(random.getrandbits(1)),
                AF=bool(random.getrandbits(1)),
                EA=bool(random.getrandbits(1)),
                DI=bool(random.getrandbits(1)),
                start_date=random_date(date(2023, 1, 1), date(2023, 6, 1)),
                end_date=random_date(date(2023, 6, 2), date(2023, 12, 31)),
                edited_by=editor.username
            )
            session.add(project)
            project_list.append(project)
        session.commit()

        # --- Create project details ---
        manager_users = [user for user in user_list if user.is_manager]
        for project in project_list:
            for user in user_list:
                editor = random.choice(user_list)
                detail = ProjectDetail(
                    details_id=uuid.uuid4(),
                    project_id=project.project_id,
                    employee_id=user.id,
                    role_id=random.choice(role_list).role_id,
                    status=random.choice(list(ProjectStatusEnum)).value,
                    manager_approved=bool(random.getrandbits(1)),
                    approved_manager=random.choice(manager_users).id,
                    admin_approved=random.choice(list(ProjectDetailsStatusEnum)).value,
                    last_edited_on=datetime.utcnow(),
                    last_edited_by=editor.id,
                    remark="Auto-generated remark"
                )
                session.add(detail)

        # --- Create project history ---
        for project in project_list:
            for user in user_list:
                history = ProjectHistory(
                    history_id=uuid.uuid4(),
                    project_id=project.project_id,
                    employee_id=user.id,
                    start_date=random_date(date(2022, 1, 1), date(2022, 6, 1)),
                    end_date=random_date(date(2022, 6, 2), date(2022, 12, 31))
                )
                session.add(history)

        session.commit()
        print("Data seeded successfully!")