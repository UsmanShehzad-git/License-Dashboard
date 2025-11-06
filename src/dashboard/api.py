import os
import secrets
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fastapi import APIRouter, Form, Request, status, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from src.dashboard.models import ActivateLicense,TrialLicense
from src.dashboard.database import SessionLocal, init_db, User, SessionToken, LicenseEntry,LicenseTokenStore
import subprocess
import json

load_dotenv()
init_db()

router = APIRouter()
templates = Jinja2Templates(directory="templates")
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",".."))
COUNTRY_CODES_PATH = os.path.join(ROOT_DIR, "country_code.json")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def is_valid_country_code(code: str) -> bool:
    try:
        with open(COUNTRY_CODES_PATH, "r") as f:
            countries = json.load(f)
        valid_codes = {entry["code"].upper() for entry in countries}
        return code.upper() in valid_codes
    except Exception as e:
        print(f"Error loading country codes: {e}")
        return False

@router.get("/", response_class=HTMLResponse)
async def login_get(request: Request, error: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@router.post("/login")
async def login_post(request: Request,email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=email, password=password).first()

    if user:
        token = secrets.token_hex(32)
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=30)

        session_token = SessionToken(email=email, token=token, created_at=now, expires_at=expires_at)
        db.add(session_token)
        db.commit()

        response = RedirectResponse(url=request.url_for("dashboard"), status_code=status.HTTP_302_FOUND)
        response.set_cookie(key="session_token", value=token, httponly=True)
        return response
    else:
        return RedirectResponse(url=request.url_for("login_get") + "?error=Invalid+email+or+password", status_code=status.HTTP_302_FOUND)

@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session_token")

    if token:
        session = db.query(SessionToken).filter_by(token=token).first()
        if session:
            db.delete(session)
            db.commit()

    response = RedirectResponse(url=request.url_for("login_get"), status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_token")
    return response

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session_token")

    if not token:
        return RedirectResponse(url=request.url_for("login_get"), status_code=status.HTTP_302_FOUND)

    session = db.query(SessionToken).filter_by(token=token).first()

    if not session or session.expires_at < datetime.utcnow():
        return RedirectResponse(url=request.url_for("login_get"), status_code=status.HTTP_302_FOUND)

    licenses = db.query(LicenseEntry).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "licenses": licenses
    })

@router.post("/add_license")
async def add_license(
    countrycode: str = Form(...),
    companyname: str = Form(...),
    license_type: str = Form(...),
    hash_value: str = Form(...),
    device_limit: int = Form(...),
    validity: str = Form(...),
    db: Session = Depends(get_db)
):
    # ✅ Step 1: Check country code
    if not is_valid_country_code(countrycode):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Invalid country code. Please provide a valid ISO 3166-1 code."}
        )

    # ✅ Step 2: Check for duplicates
    existing_license = db.query(LicenseEntry).filter(
        (LicenseEntry.companyname.ilike(companyname)) | (LicenseEntry.hash_value == hash_value)
    ).first()
    if existing_license:
        if existing_license.companyname.lower() == companyname.lower():
            msg = "A license for this company already exists."
        else:
            msg = "A license with this hash_value already exists."
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": msg})

    # ✅ Step 3: Validate license type
    if license_type.lower() == "distributor":
        license_type_flag = 1
    elif license_type.lower() == "reseller":
        license_type_flag = 0
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Invalid license_type. Must be 'Distributor' or 'Reseller'."}
        )

    # ✅ Step 4: Generate token using subprocess
    try:
        result = subprocess.run(
            [
                "java", "-jar", "cyber.jar",
                countrycode, companyname, str(license_type_flag),
                validity, hash_value, str(device_limit)
            ],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip().splitlines()
        if not output:
            raise Exception("No output from cyber.jar")
        token = output[-1]
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"message": f"Failed to generate token: {e}"}
        )

    # ✅ Step 5: Save license entry
    new_license = LicenseEntry(
        countrycode=countrycode,
        companyname=companyname,
        license_type=license_type,
        hash_value=hash_value,
        device_limit=str(device_limit),
        validity=validity
    )
    db.add(new_license)
    db.commit()

    # ✅ Step 6: Calculate expiry
    try:
        validity_days = int(validity)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid validity value")

    now = datetime.now(timezone.utc)
    expiry_date = now + timedelta(days=validity_days)

    license_token = LicenseTokenStore(
        company_name=companyname,
        token=token,
        created_at=now,
        expired_at=expiry_date
    )
    db.add(license_token)
    db.commit()

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "company_name": companyname,
            "license_token": token,
            "valid_from": now.date().isoformat(),
            "valid_till": expiry_date.date().isoformat(),
        }
    )

# @router.post("/add_license")
# async def add_license(
#     countrycode: str = Form(...),
#     companyname: str = Form(...),
#     license_type: str = Form(...),
#     hash_value: str = Form(...),
#     device_limit: int = Form(...),
#     validity: str = Form(...),
#     db: Session = Depends(get_db)
# ):
#     existing_license = db.query(LicenseEntry).filter(
#         (LicenseEntry.companyname.ilike(companyname)) | (LicenseEntry.hash_value == hash_value)
#     ).first()
#     if existing_license:
#         if existing_license.companyname.lower() == companyname.lower():
#             msg = "A license for this company already exists."
#         else:
#             msg = "A license with this hash_value already exists."
#         return JSONResponse(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             content={"message": msg}
#         )

#     token = secrets.token_hex(16)

#     new_license = LicenseEntry(
#         countrycode=countrycode,
#         companyname=companyname,
#         license_type=license_type,
#         hash_value=hash_value,
#         device_limit=str(device_limit),
#         validity=validity
#     )
#     db.add(new_license)
#     db.commit()

#     try:
#         validity_days = int(validity)
#     except ValueError:
#         raise HTTPException(status_code=400, detail="Invalid validity value")

#     now = datetime.now(timezone.utc)
#     expiry_date = now + timedelta(days=validity_days)

#     license_token = LicenseTokenStore(
#         company_name=companyname,
#         token=token,
#         created_at=now,
#         expired_at=expiry_date
#     )
#     db.add(license_token)
#     db.commit()

#     return JSONResponse(
#         status_code=status.HTTP_201_CREATED,
#         content={
#             "company_name": companyname,
#             "license_token": token,
#             "valid_from": now.date().isoformat() if now else None,
#             "valid_till": expiry_date.date().isoformat() if expiry_date else None,
#         }
# )

@router.get("/get_licenses")
async def get_licenses(db: Session = Depends(get_db), request: Request = None):

    token = request.cookies.get("session_token") if request else None
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    licenses = db.query(LicenseEntry).all()
    now = datetime.now(timezone.utc)
    result = []

    for lic in licenses:
        token_entry = db.query(LicenseTokenStore).filter_by(company_name=lic.companyname).order_by(LicenseTokenStore.created_at.desc()).first()
        expired_at = token_entry.expired_at if token_entry else None
        created_at = token_entry.created_at if token_entry else None
        activation_time = token_entry.activation_time if token_entry else None
        activated_by = token_entry.activated_by if token_entry else None
        

        # Ensure timezone-aware
        if expired_at and expired_at.tzinfo is None:
            expired_at = expired_at.replace(tzinfo=timezone.utc)
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        status = "Inactive"
        if token_entry and token_entry.is_active:
            if expired_at and expired_at > now:
                status = "Active"
            else:
                status = "Expired"

        result.append({
            "id": lic.id,
            "hash_value": lic.hash_value,           
            "companyname": lic.companyname,
            "countrycode": lic.countrycode,
            "license_type": lic.license_type,
            "device_limit": lic.device_limit,
            "validity": lic.validity,
            "valid_from": created_at.date().isoformat() if created_at else None,
            "valid_till": expired_at.date().isoformat() if expired_at else None,
            "status": status,
            "activation_time": activation_time.strftime("%Y-%m-%d %H:%M:%S") if activation_time else None,
            "activated_by": activated_by,
        })

    return JSONResponse(content=result)

@router.delete("/delete_license/{license_id}")
async def delete_license(license_id: int, db: Session = Depends(get_db)):
    license_entry = db.query(LicenseEntry).filter_by(id=license_id).first()

    if not license_entry:
        raise HTTPException(status_code=404, detail=f"License with ID {license_id} not found")

    db.query(LicenseTokenStore).filter_by(company_name=license_entry.companyname).delete()

    db.delete(license_entry)
    db.commit()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": f"License with ID {license_id} and its tokens deleted successfully.",
            "deleted_license": {
                "id": license_entry.id,
                "company_name": license_entry.companyname
            }
        }
    )

@router.get("/view_license/{license_id}")
async def view_license(license_id: int, db: Session = Depends(get_db)):
    license_entry = db.query(LicenseEntry).filter_by(id=license_id).first()

    if not license_entry:
        raise HTTPException(status_code=404, detail="License not found")

    token_entry = db.query(LicenseTokenStore).filter_by(company_name=license_entry.companyname).order_by(LicenseTokenStore.created_at.desc()).first()

    return JSONResponse(
        content={
            "id": license_entry.id,
            "hash_value": license_entry.hash_value,
            "companyname": license_entry.companyname,
            "countrycode": license_entry.countrycode,
            "license_type": license_entry.license_type,
            "device_limit": license_entry.device_limit,
            "validity": license_entry.validity,
            "token": token_entry.token if token_entry else None,
            "valid_from": token_entry.created_at.date().isoformat() if token_entry else None,
            "valid_till": token_entry.expired_at.date().isoformat() if token_entry else None,
            "activation_time": token_entry.activation_time.strftime("%Y-%m-%d %H:%M:%S") if token_entry and token_entry.activation_time else None,
            "activated_by": token_entry.activated_by if token_entry else None,
        }
    )

# @router.post("/edit_license/{license_id}")
# async def edit_license(
#     license_id: int,
#     license_type: str = Form(...),
#     device_limit: int = Form(...),
#     validity: str = Form(...),
#     db: Session = Depends(get_db)
# ):
#     license_entry = db.query(LicenseEntry).filter_by(id=license_id).first()
#     if not license_entry:
#         return JSONResponse(status_code=404, content={"message": "License not found"})

#     try:
#         validity_days = int(validity)
#     except ValueError:
#         return JSONResponse(status_code=400, content={"message": "Invalid validity value"})

#     license_entry.license_type = license_type
#     license_entry.device_limit = str(device_limit)
#     license_entry.validity = validity
#     db.commit()

#     now = datetime.now(timezone.utc)
#     expiry_date = now + timedelta(days=validity_days)
#     new_token = secrets.token_hex(16)
#     license_token = LicenseTokenStore(
#         company_name=license_entry.companyname,
#         token=new_token,
#         created_at=now,
#         expired_at=expiry_date,
#         is_active=False 
#     )
#     db.add(license_token)
#     db.commit()

#     return JSONResponse(
#     status_code=200,
#     content={
#         "company_name": license_entry.companyname,
#         "license_token": new_token,
#         "valid_from": now.date().isoformat(),
#         "valid_till": expiry_date.date().isoformat(),
#     }
# )

@router.post("/edit_license/{license_id}")
async def edit_license(
    license_id: int,
    license_type: str = Form(...),
    device_limit: int = Form(...),
    validity: str = Form(...),
    db: Session = Depends(get_db)
):
    license_entry = db.query(LicenseEntry).filter_by(id=license_id).first()
    if not license_entry:
        return JSONResponse(status_code=404, content={"message": "License not found"})

    try:
        validity_days = int(validity)
    except ValueError:
        return JSONResponse(status_code=400, content={"message": "Invalid validity value"})

    license_entry.license_type = license_type
    license_entry.device_limit = str(device_limit)
    license_entry.validity = validity
    db.commit()

    if license_type.lower() == "distributor":
        license_type_flag = 1
    elif license_type.lower() == "reseller":
        license_type_flag = 0
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Invalid license_type. Must be 'Distributor' or 'Reseller'."}
        )

    now = datetime.now(timezone.utc)
    expiry_date = now + timedelta(days=validity_days)

    try:
        result = subprocess.run(
            [
                "java", "-jar", "cyber.jar",
                license_entry.countrycode,
                license_entry.companyname,
                str(license_type_flag),
                validity,
                license_entry.hash_value,
                str(device_limit)
            ],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip().splitlines()
        if not output:
            raise Exception("No output from cyber.jar")
        new_token = output[-1]
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"message": f"Failed to generate token: {e}"}
        )

    license_token = LicenseTokenStore(
        company_name=license_entry.companyname,
        token=new_token,
        created_at=now,
        expired_at=expiry_date,
        is_active=False 
    )
    db.add(license_token)
    db.commit()

    return JSONResponse(
        status_code=200,
        content={
            "company_name": license_entry.companyname,
            "license_token": new_token,
            "valid_from": now.date().isoformat(),
            "valid_till": expiry_date.date().isoformat(),
        }
    )

# @router.post("/activate_license")
# async def activate_license(
#     data: ActivateLicense,
#     db: Session = Depends(get_db)
# ):
#     hash_value = data.hash_value
#     email = data.email if hasattr(data, "email") and data.email else ""

#     if not hash_value:
#         return JSONResponse(status_code=400, content={"message": "hash_value is required"})

#     license_entry = db.query(LicenseEntry).filter_by(hash_value=hash_value).first()
#     if not license_entry:
#         return JSONResponse(status_code=404, content={"message": "License not found"})

#     token_entry = db.query(LicenseTokenStore).filter_by(company_name=license_entry.companyname).order_by(LicenseTokenStore.created_at.desc()).first()
#     if not token_entry:
#         return JSONResponse(status_code=404, content={"message": "License token not found"})

#     token_entry.is_active = True
#     token_entry.activation_time = datetime.now(timezone.utc)
#     token_entry.activated_by = email 
#     db.commit()
#     return JSONResponse(
#         status_code=200,
#         content={
#             "message": "License activated",
#             "license_id": license_entry.id,
#         }
#     )

def activate_license_by_hash(db: Session, hash_value: str, email: str = "") -> bool:
    if not hash_value:
        return False

    license_entry = db.query(LicenseEntry).filter_by(hash_value=hash_value).first()
    if not license_entry:
        return False

    token_entry = db.query(LicenseTokenStore).filter_by(company_name=license_entry.companyname).order_by(LicenseTokenStore.created_at.desc()).first()
    if not token_entry:
        return False

    token_entry.is_active = True
    token_entry.activation_time = datetime.now(timezone.utc)
    token_entry.activated_by = email
    db.commit()
    return True

@router.post("/activate_license")
async def activate_license(
    data: ActivateLicense,
    db: Session = Depends(get_db)
):
    success = activate_license_by_hash(db, data.hash_value, getattr(data, "email", ""))
    if success:
        license_entry = db.query(LicenseEntry).filter_by(hash_value=data.hash_value).first()
        return JSONResponse(
            status_code=200,
            content={
                "message": "License activated",
                "license_id": license_entry.id if license_entry else None,
            }
        )
    else:
        return JSONResponse(
            status_code=400,
            content={"message": "License not activated"}
        )
    
@router.post("/trial_license")
async def trail_license(
    data: TrialLicense,
    db: Session = Depends(get_db)
):
    countrycode = data.countrycode
    companyname = data.companyname
    license_type = data.license_type
    hash_value = data.hash_value
    email = data.email
    validity = "30"
    device_limit = "5"

    if not all([countrycode, companyname, license_type, hash_value,email]):
        return JSONResponse(
            status_code=400,
            content={"message": "countrycode, companyname, license_type, and hash_value, email are required"}
        )
    
    try:
        validity_days = int(validity)
    except ValueError:
        return JSONResponse(status_code=400, content={"message": "Invalid validity value"})

    if license_type.lower() == "distributor":
        license_type_flag = "1"
    elif license_type.lower() == "reseller":
        license_type_flag = "0"
    else:
        return JSONResponse(
            status_code=400,
            content={"message": "Invalid license_type. Must be 'Distributor' or 'Reseller'."}
        )

    try:
        result = subprocess.run(
            [
                "java", "-jar", "cyber.jar",
                countrycode, companyname, license_type_flag, validity, hash_value, device_limit
            ],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip().splitlines()
        if not output:
            raise Exception("No output from cyber.jar")
        license_key = output[-1]  # Adjust if needed
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"message": f"Failed to generate license: {e}"}
        )
    
    existing_token = db.query(LicenseTokenStore).filter_by(token=license_key, activated_by=email).first()
    if existing_token:
        activated = activate_license_by_hash(db, hash_value, email)
        return JSONResponse(
            status_code=200,
            content={
                "message": "License already exists for this email",
                "license_key": license_key
            }
        )
    
    now = datetime.now(timezone.utc)
    expiry_date = now + timedelta(days=validity_days)

    new_license = LicenseEntry(
        countrycode=countrycode,
        companyname=companyname,
        license_type=license_type,
        hash_value=hash_value,
        device_limit=device_limit,
        validity=validity
    )
    db.add(new_license)
    db.commit()

    license_token = LicenseTokenStore(
        company_name=companyname,
        token=license_key,
        created_at=now,
        expired_at=expiry_date
    )
    db.add(license_token)
    db.commit()

    activated = activate_license_by_hash(db, hash_value, email)
    if activated:
        return JSONResponse(
            status_code=200,
            content={"license_key": license_key}
        )
    else:
        return JSONResponse(
            status_code=200,
            content={"message": "License created but not activated", "license_key": license_key}
        )