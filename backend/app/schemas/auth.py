from pydantic import BaseModel


class LocalLoginRequest(BaseModel):
    email: str
    password: str
