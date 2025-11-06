from sqlalchemy import create_engine, Column, Integer, String, DateTime,Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = "sqlite:///./License.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

class SessionToken(Base):
    __tablename__ = 'session_tokens'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

class LicenseEntry(Base):
    __tablename__ = 'license_entries'
    id = Column(Integer, primary_key=True, index=True)
    countrycode = Column(String)
    companyname = Column(String)
    license_type = Column(String)
    hash_value = Column(String)
    device_limit = Column(String)
    validity = Column(String)

class LicenseTokenStore(Base):
    __tablename__ = 'license_token_store'
    id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String, nullable=False)
    token = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expired_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=False)
    activation_time = Column(DateTime, nullable=True)
    activated_by = Column(String, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    existing_user = db.query(User).filter_by(email=os.getenv("VALID_EMAIL")).first()

    if not existing_user:
        default_user = User(
            email=os.getenv("VALID_EMAIL"),
            password=os.getenv("VALID_PASSWORD")
        )
        db.add(default_user)
        db.commit()
    else:
        print("Default User Already Exist !")
    db.close()