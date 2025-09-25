from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# URL externa de la base de datos (la recomendada para usar desde fuera de Render)
DATABASE_URL = "postgresql://cookcambd_user:HOM6Vqk6KneG5hCdBSYPSybYo1BBaf5W@dpg-d3aafkidbo4c738ls860-a.oregon-postgres.render.com/cookcambd"

# Crear el engine
engine = create_engine(DATABASE_URL)

# Crear sesión local
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para los modelos
Base = declarative_base()
