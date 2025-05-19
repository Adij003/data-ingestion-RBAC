from sqlalchemy import Column, String, Boolean 
from core.database import Base
import uuid
from sqlalchemy.dialects.postgresql import UUID

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    emp_id = Column(String, unique=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    username = Column(String, index=True)
    email = Column(String, unique=True, index=True)  
    password = Column(String, unique=True, index=True)
    is_manager = Column(Boolean, index=True)  
    is_admin = Column(Boolean, index=True)  
    is_active = Column(Boolean, index=True)  
