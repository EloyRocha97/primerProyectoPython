from typing import Optional
from pydantic import BaseModel,EmailStr

class Client(BaseModel):
    id: Optional[str] = None
    username: str
    email: EmailStr  # Esto valida que el campo 'email' sea un formato de correo electrónico válido
    password: str