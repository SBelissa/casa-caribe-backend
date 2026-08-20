from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

# --- USUARIOS ---
class UsuarioRegistro(BaseModel):
    nombre_completo: str
    correo: EmailStr
    telefono: str
    password: str

class UsuarioLogin(BaseModel):
    correo: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- RESERVAS ---
class ReservaCrear(BaseModel):
    fecha: str  # YYYY-MM-DD
    hora: str   # HH:MM
    numero_personas: int = Field(gt=0, le=20)
    observaciones: Optional[str] = None

class ReservaActualizar(BaseModel):
    fecha: Optional[str] = None
    hora: Optional[str] = None
    numero_personas: Optional[int] = None
    observaciones: Optional[str] = None
    estado: Optional[str] = None

class ReservaRespuesta(BaseModel):
    id: str
    cliente_id: str
    fecha: str
    hora: str
    numero_personas: int
    observaciones: Optional[str]
    estado: str
    fecha_creacion: datetime
