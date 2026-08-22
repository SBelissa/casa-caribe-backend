import os
import smtplib
from datetime import datetime, timedelta
from typing import Optional, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
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

# Lista de orígenes permitidos para CORS
origins = [
    "https://comforting-gumption-884495.netlify.app",  # Netlify
    "http://localhost:5173",                            # React / Vite local
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]

# Configuración del Sistema
MONGO_URI = os.getenv("MONGO_URI", "")
SECRET_KEY = os.getenv("SECRET_KEY", "secret_default")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Variables para envío de Correos
GMAIL_USER = os.getenv("GMAIL_USER", "")  # Ej: tu_correo@gmail.com
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")  # Tu App Password de 16 dígitos

client = AsyncIOMotorClient(MONGO_URI)
db = client.casa_caribe

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="Casa Caribe API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- FUNCIÓN PARA ENVIAR CORREOS REALES ---
def enviar_correo_confirmacion(email_destinatario: str, nombre_cliente: str, fecha: str, hora: str, personas: int):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("⚠️ GMAIL_USER o GMAIL_APP_PASSWORD no están configurados en el .env / Render. Correo omitido.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = f"Casa Caribe <{GMAIL_USER}>"
        msg['To'] = email_destinatario
        msg['Subject'] = "¡Tu mesa en Casa Caribe ha sido confirmada! 🌊"

        cuerpo_html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #20261F; background-color: #FBF3E6; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background: white; padding: 25px; border-radius: 12px; border: 1px solid #0B3D3A;">
                    <h2 style="color: #082B29; margin-top: 0;">¡Hola {nombre_cliente}!</h2>
                    <p>Nos alegra informarte que tu solicitud de reserva en <strong>Casa Caribe</strong> ha sido <strong>confirmada</strong>.</p>
                    
                    <div style="background-color: #C7E3D4; padding: 15px; border-radius: 8px; margin: 20px 0; color: #082B29;">
                        <p style="margin: 5px 0;"><strong>Personas:</strong> {personas}</p>
                        <p style="margin: 5px 0;"><strong>Fecha:</strong> {fecha}</p>
                        <p style="margin: 5px 0;"><strong>Hora:</strong> {hora}</p>
                    </div>

                    <p style="font-size: 13px; color: #666;">Si llegas más de 15 minutos tarde o necesitas cancelar, por favor responde a este correo.</p>
                    <p style="margin-top: 20px; font-weight: bold; color: #E8613D;">¡Nos vemos pronto!</p>
                </div>
            </body>
        </html>
        """
        msg.attach(MIMEText(cuerpo_html, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)
            
        print(f"✅ Correo enviado exitosamente a: {email_destinatario}")
    except Exception as e:
        print(f"❌ Error enviando correo: {e}")


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

async def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("rol", "").lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos de administrador."
        )
    return current_user

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
            "email": usuario["correo"],
            "rol": usuario.get("rol", "Cliente")
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
async def listar_todas_reservas(current_user: dict = Depends(get_current_admin)):
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
async def decidir_reserva(
    reserva_id: str, 
    decision: DecisionReserva, 
    background_tasks: BackgroundTasks, 
    current_user: dict = Depends(get_current_admin)
):
    # 1. Buscar la reserva actual
    reserva = await db.reservas.find_one({"_id": ObjectId(reserva_id)})
    if not reserva:
        raise HTTPException(status_code=404, detail="Reserva no encontrada")

    # 2. Actualizar el estado en MongoDB
    await db.reservas.update_one(
        {"_id": ObjectId(reserva_id)},
        {"$set": {"estado": decision.estado}}
    )

    # 3. Si la decisión es 'confirmada', enviar el correo en segundo plano
    if decision.estado == "confirmada":
        correo_destinatario = reserva.get("cliente", {}).get("correo")
        nombre_cliente = reserva.get("cliente", {}).get("nombre", "Cliente")
        
        if correo_destinatario:
            background_tasks.add_task(
                enviar_correo_confirmacion,
                email_destinatario=correo_destinatario,
                nombre_cliente=nombre_cliente,
                fecha=reserva.get("fecha", ""),
                hora=reserva.get("hora", ""),
                personas=reserva.get("cantidad_personas", 1)
            )

    return {"mensaje": f"Reserva actualizada a {decision.estado}"}