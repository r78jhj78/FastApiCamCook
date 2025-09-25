# from fastapi import FastAPI, Depends, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from typing import Optional, List
# from jose import JWTError, jwt
# from pydantic import BaseModel
# from passlib.context import CryptContext
# from datetime import datetime, timedelta

# # Simulación de base de datos (reemplazar con DB real)
# fake_users_db = {}
# fake_recipes_db = []
# fake_proveedores_db = []

# # App
# app = FastAPI()

# # Seguridad
# SECRET_KEY = "secreto_super_seguro"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# # Modelos

# class User(BaseModel):
#     username: str
#     full_name: Optional[str] = None
#     password: str
#     role: str  # admin, cocinero, usuario, proveedor

# class UserInDB(User):
#     hashed_password: str

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# class Recipe(BaseModel):
#     id: int
#     title: str
#     ingredients: List[str]
#     author: str
#     approved: bool = False

# class Proveedor(BaseModel):
#     username: str
#     alimento: str
#     telefono: str

# # Utilidades

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def get_user(username: str):
#     return fake_users_db.get(username)

# def authenticate_user(username: str, password: str):
#     user = get_user(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         return None
#     return UserInDB(**user)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=401,
#         detail="No se pudo validar las credenciales",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     user = get_user(username)
#     if user is None:
#         raise credentials_exception
#     return UserInDB(**user)

# async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
#     return current_user

# def require_role(role: str):
#     async def _role_dep(user: UserInDB = Depends(get_current_active_user)):
#         if user.role != role:
#             raise HTTPException(status_code=403, detail=f"Solo para {role}s")
#         return user
#     return _role_dep

# # Endpoints

# @app.post("/register", response_model=Token)
# def register(user: User):
#     if user.username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Usuario ya existe")
#     hashed = get_password_hash(user.password)
#     fake_users_db[user.username] = {
#         "username": user.username,
#         "full_name": user.full_name,
#         "role": user.role,
#         "hashed_password": hashed
#     }
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/token", response_model=Token)
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(status_code=400, detail="Credenciales incorrectas")
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/recetas/crear", dependencies=[Depends(require_role("cocinero"))])
# def crear_receta(receta: Recipe, user: UserInDB = Depends(get_current_active_user)):
#     receta.id = len(fake_recipes_db) + 1
#     receta.author = user.username
#     fake_recipes_db.append(receta)
#     return {"mensaje": "Receta creada. Esperando aprobación.", "receta": receta}

# @app.get("/recetas", response_model=List[Recipe])
# def ver_recetas():
#     return [r for r in fake_recipes_db if r.approved]

# @app.get("/recetas/pendientes", dependencies=[Depends(require_role("admin"))])
# def recetas_pendientes():
#     return [r for r in fake_recipes_db if not r.approved]

# @app.post("/recetas/aprobar/{receta_id}", dependencies=[Depends(require_role("admin"))])
# def aprobar_receta(receta_id: int):
#     for r in fake_recipes_db:
#         if r.id == receta_id:
#             r.approved = True
#             return {"mensaje": "Receta aprobada"}
#     raise HTTPException(status_code=404, detail="Receta no encontrada")

# @app.post("/proveedor/subir", dependencies=[Depends(require_role("proveedor"))])
# def subir_proveedor(info: Proveedor):
#     fake_proveedores_db.append(info)
#     return {"mensaje": "Proveedor registrado", "data": info}

# @app.get("/proveedores", response_model=List[Proveedor])
# def listar_proveedores():
#     return fake_proveedores_db



#probando el fastApi

# from database import engine
# import models
# from fastapi import Depends
# from sqlalchemy.orm import Session
# from database import SessionLocal
# from fastapi import FastAPI

# app = FastAPI()
# models.Base.metadata.create_all(bind=engine)

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.get("/")
# def root():
#     return {"message": "Bienvenido a la API de CamCook"}

# @app.get("/usuarios")
# def obtener_usuarios(db: Session = Depends(get_db)):
#     return db.query(models.User).all()

from database import engine
import models
from fastapi import Depends
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import FastAPI
from models import User
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError

app = FastAPI()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Bienvenido a la API de CamCook"}

@app.post("/register")
def register_user(username: str, password: str, role: str, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Usuario creado", "user": user.username}

@app.get("/usuarios")
def obtener_usuarios(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.on_event("startup")
def crear_usuarios_de_prueba():
    db = SessionLocal()
    try:
        usuarios_prueba = [
            {"username": "chef1", "password": "1234", "role": "cocinero"},
            {"username": "user1", "password": "1234", "role": "usuario"},
            {"username": "proveedor1", "password": "1234", "role": "proveedor"},
            {"username": "admin1", "password": "adminpass", "role": "admin"},
        ]

        for u in usuarios_prueba:
            # Verificamos si ya existe
            if not db.query(User).filter_by(username=u["username"]).first():
                hashed = pwd_context.hash(u["password"])
                nuevo_usuario = User(username=u["username"], hashed_password=hashed, role=u["role"])
                db.add(nuevo_usuario)
        db.commit()
    except IntegrityError:
        db.rollback()
    finally:
        db.close()