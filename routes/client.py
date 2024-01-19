from fastapi import APIRouter, Depends, HTTPException, status
from config.db import db_client
from models.client import Client
from schemas.client import client_schema, clients_schema
from bson import ObjectId
from typing import Optional
from pydantic import BaseModel
#jwt↓
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
import bcrypt

# .env↓
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


client = APIRouter()

# JWT ↓

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta # utcnow() devuelve la fecha y hora actuales en formato UTC
    else:
        expire = datetime.utcnow() + timedelta(days=1) # podira ser en minutos = (minutes=20)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class Token(BaseModel):
    access_token: str
    token_type: str

# Clase para los datos del token
class TokenData(BaseModel):
    username: Optional[str] = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

#JWT ↑

@client.post("/register", response_model=Client)
def register_new_client(client: Client):
    # Verificar si el usuario ya existe
    existing_user = db_client.clients.find_one({"username": client.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Encriptar la contraseña antes de guardarla
    hashed_password = bcrypt.hashpw(client.password.encode('utf-8'), bcrypt.gensalt())
    
    # Crear un nuevo cliente con la contraseña encriptada
    new_client_dict = dict(client)
    new_client_dict['password'] = hashed_password.decode('utf-8')  # Almacena el hash en la base de datos
    
    inserted_client = db_client.clients.insert_one(new_client_dict)
    
    del new_client_dict['id']
    new_client_id = str(inserted_client.inserted_id)
    
    new_client = Client(id=new_client_id, **new_client_dict)

    return new_client

@client.get("/verify", response_model=Client)
def verify_user(current_user: TokenData = Depends(get_current_user)):
    user = db_client.clients.find_one({"username": current_user.username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@client.get("/")
def find_old_clients():
    try:
        clients = db_client.clients.find()
        return clients_schema(clients)
    except Exception as e:
        return {"message": f"An error occurred: {str(e)}"}

@client.get("/{id}")
def find_client_by_id(id: str):
    try:
        client_data = db_client.clients.find_one({"_id": ObjectId(id)})
        if client_data:
            return client_schema(client_data)
        else:
            return {"message": "Client not found"}
    except Exception as e:
        return {"message": str(e)}

@client.put("/{id}", response_model=Client)
def edit_client(id: str, client_data: Client):
    try:
        update_data = dict(client_data)
        del update_data['id']
        
        # Actualizo
        updated_client = db_client.clients.find_one_and_update(
            {"_id": ObjectId(id)},
            {"$set": update_data},
            return_document=True  # para retornar el actualizado
        )

        if updated_client:
            return client_schema(updated_client)
        else:
            return {"message": "Client not found"}
    except Exception as e:
        return {"message": str(e)}

@client.delete("/{id}", response_model=dict)
def delete_client(id: str):
    try:
        deletion_result = db_client.clients.delete_one({"_id": ObjectId(id)})
        
        if deletion_result.deleted_count > 0:
            return {"message": "Client deleted successfully"}
        else:
            return {"message": "Client not found"}
    except Exception as e:
        return {"message": str(e)}