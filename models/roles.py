from  sqlalchemy import  Column , Integer , String ,Date , DateTime
from  core.database  import   Base
import  uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
class Role(Base):
    __tablename__ = "roles"
    role_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_name = Column(String, unique=True, index=True, nullable=False)
    role_description = Column(String, default="")
    edited_on = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    edited_by = Column(String)



