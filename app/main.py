import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher


from dotenv import load_dotenv
# Cargar variables desde el archivo .env
load_dotenv()


# Configuración
MONGO_URI = os.getenv("MONGO_URI", "")
SECRET_KEY = os.getenv("SECRET_KEY", "secret_default")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

client = AsyncIOMotorClient(MONGO_URI)
db = client.casa_caribe

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="Casa Caribe API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Esquemas de Entrada
class UsuarioRegistro(BaseModel):
    nombre_completo: str
    correo: EmailStr
    telefono: Optional[str] = ""
    password: str

class UsuarioLogin(BaseModel):
    correo: EmailStr
    password: str

class ReservaCrear(BaseModel):
    fecha: str
    hora: str
    cantidad_personas: int = Field(gt=0)
    tipo_mesa: Optional[str] = "terraza"
    notas: Optional[str] = ""

class DecisionReserva(BaseModel):
    estado: str  # "confirmada" o "cancelada"

# Funciones de Autenticación

# Forzar el uso de Bcrypt en lugar de Argon2
password_hash = PasswordHash((BcryptHasher(),))

def hash_password(password: str):
    return password_hash.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return password_hash.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de autenticación no válidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id: str = payload.get("sub")
        if usuario_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    usuario = await db.usuarios.find_one({"_id": ObjectId(usuario_id)})
    if usuario is None:
        raise credentials_exception
    return {
        "id": str(usuario["_id"]),
        "nombre_completo": usuario["nombre_completo"],
        "correo": usuario["correo"],
        "rol": usuario.get("rol", "Cliente")
    }

# Rutas de Autenticación
@app.post("/api/auth/registro", status_code=201)
async def registrar(usuario: UsuarioRegistro):
    existe = await db.usuarios.find_one({"correo": usuario.correo})
    if existe:
        raise HTTPException(status_code=400, detail="El correo electrónico ya se encuentra registrado.")
    
    nuevo_usuario = {
        "nombre_completo": usuario.nombre_completo,
        "correo": usuario.correo,
        "telefono": usuario.telefono,
        "password_hash": hash_password(usuario.password),
        "rol": "Cliente",
        "fecha_registro": datetime.utcnow()
    }
    resultado = await db.usuarios.insert_one(nuevo_usuario)
    return {"mensaje": "Registro realizado correctamente.", "id": str(resultado.inserted_id)}

@app.post("/api/auth/login")
async def login(credenciales: UsuarioLogin):
    usuario = await db.usuarios.find_one({"correo": credenciales.correo})
    if not usuario or not verify_password(credenciales.password, usuario["password_hash"]):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")
    
    token = create_access_token({"sub": str(usuario["_id"]), "rol": usuario.get("rol", "Cliente")})
    return {
        "access_token": token,
        "token_type": "bearer",
        "usuario": {
            "id": str(usuario["_id"]),
            "name": usuario["nombre_completo"],
            "email": usuario["correo"]
        }
    }

# Rutas de Reservas
@app.post("/api/reservas", status_code=201)
async def crear_reserva(reserva: ReservaCrear, current_user: dict = Depends(get_current_user)):
    nueva_reserva = {
        "cliente": {
            "_id": ObjectId(current_user["id"]),
            "nombre": current_user["nombre_completo"],
            "correo": current_user["correo"]
        },
        "fecha": reserva.fecha,
        "hora": reserva.hora,
        "cantidad_personas": reserva.cantidad_personas,
        "tipo_mesa": reserva.tipo_mesa,
        "estado": "pendiente",
        "notas": reserva.notas,
        "created_at": datetime.utcnow()
    }
    resultado = await db.reservas.insert_one(nueva_reserva)
    nueva_reserva["_id"] = str(resultado.inserted_id)
    nueva_reserva["cliente"]["_id"] = str(nueva_reserva["cliente"]["_id"])
    return nueva_reserva

@app.get("/api/reservas/mis-reservas")
async def mis_reservas(current_user: dict = Depends(get_current_user)):
    cursor = db.reservas.find({"cliente._id": ObjectId(current_user["id"])})
    reservas = []
    async for r in cursor:
        r["id"] = str(r["_id"])
        r["cliente"]["_id"] = str(r["cliente"]["_id"])
        del r["_id"]
        reservas.append(r)
    return reservas

@app.get("/api/admin/reservas")
async def listar_todas_reservas(current_user: dict = Depends(get_current_user)):
    cursor = db.reservas.find()
    reservas = []
    async for r in cursor:
        r["id"] = str(r["_id"])
        if "cliente" in r and "_id" in r["cliente"]:
            r["cliente"]["_id"] = str(r["cliente"]["_id"])
        del r["_id"]
        reservas.append(r)
    return reservas

@app.put("/api/admin/reservas/{reserva_id}/decidir")
async def decidir_reserva(reserva_id: str, decision: DecisionReserva, current_user: dict = Depends(get_current_user)):
    resultado = await db.reservas.update_one(
        {"_id": ObjectId(reserva_id)},
        {"$set": {"estado": decision.estado}}
    )
    if resultado.modified_count == 0:
        raise HTTPException(status_code=404, detail="Reserva no encontrada")
    return {"mensaje": f"Reserva actualizada a {decision.estado}"}
