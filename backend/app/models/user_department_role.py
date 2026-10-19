import enum

from sqlalchemy import Enum, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Role(str, enum.Enum):
    viewer = "viewer"
    editor = "editor"
    admin = "admin"


class UserDepartmentRole(Base):
    __tablename__ = "user_department_roles"

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), primary_key=True)
    department_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("departments.id"), primary_key=True
    )
    role: Mapped[Role] = mapped_column(Enum(Role, name="role"), nullable=False)
