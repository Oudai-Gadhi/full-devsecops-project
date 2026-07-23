import os
import shutil
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from dotenv import load_dotenv
import uuid
from fastapi.responses import FileResponse
from pydantic import BaseModel

load_dotenv()

# --- Email Config ---
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

def send_status_email(to_email: str, claim_id: int, full_name: str, new_status: str):
    if not to_email or not SMTP_USER:
        print(f"Skipping email to {to_email} (No SMTP config or email provided)")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = f"STAR ASSURANCES <{SMTP_USER}>"
        msg['To'] = to_email
        msg['Subject'] = f"Mise à jour de votre déclaration STAR #{claim_id}"

        status_text = "en cours de révision" if new_status == "reviewed" else "clôturé"

        body = f"""
        Bonjour {full_name},

        Nous vous informons que l'état de votre déclaration d'accident #{claim_id} a été mis à jour.

        Nouvel état : {status_text.upper()}

        Merci de votre confiance,
        L'équipe STAR ASSURANCES Tunisie.
        """
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# --- Auth Config ---
# JWT_SECRET must come from the environment (k8s Secret) - no hardcoded fallback.
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
COOKIE_NAME = "star_admin_session"
# Cookies only work over HTTPS when secure=True. Set COOKIE_SECURE=false in
# your dev environment (e.g. plain-http minikube) and true anywhere real.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Upload validation config ---
# Client-side <input accept> is cosmetic only - this is the real gate.
ALLOWED_CONTENT_TYPES = {"application/pdf", "image/jpeg", "image/png"}
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
# Real magic-byte signatures, since both filename and content_type are
# fully client-supplied and spoofable. This is a first-line check only -
# the YARA/ClamAV pipeline downstream remains the authoritative scan.
MAGIC_SIGNATURES = {
    ".pdf": [b"%PDF"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
}

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- SCAN AND CLEAN DIRECTORY ---
SCAN_INPUT_DIR = os.environ.get("SCAN_INPUT_DIR", "/mnt/scan-input")
CLEAN_OUTPUT_DIR = os.environ.get("CLEAN_OUTPUT_DIR", "/mnt/clean-output")

os.makedirs(SCAN_INPUT_DIR, exist_ok=True)

# --- Models ---
class Claim(Base):
    __tablename__ = "claims"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255))
    email = Column(String(255), nullable=True)
    cin = Column(String(50))
    policy_number = Column(String(100))
    phone_number = Column(String(20))
    vehicle_details = Column(Text)
    status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    attachments = relationship("Attachment", back_populates="claim")

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True, index=True)
    claim_id = Column(Integer, ForeignKey("claims.id"))
    file_name = Column(String(255))
    file_path = Column(String(255))          # kept, no longer used to locate the file
    file_type = Column(String(50))
    stored_filename = Column(String(255), nullable=True)  # used to look the file up on clean-output
    claim = relationship("Claim", back_populates="attachments")

class AdminUser(Base):
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

def init_db():
    retries = 10
    while retries > 0:
        try:
            print(f"Connecting to database at {DATABASE_URL}...")
            Base.metadata.create_all(bind=engine)

            # Simple migration hack for existing DB
            with engine.connect() as conn:
                # Add email column if not exists
                try:
                    conn.execute(text("ALTER TABLE claims ADD COLUMN email VARCHAR(255) NULL AFTER full_name"))
                    conn.commit()
                    print("Database migrated: added email column")
                except Exception:
                    pass

                # Add stored_filename column if not exists
                try:
                    conn.execute(text("ALTER TABLE attachments ADD COLUMN stored_filename VARCHAR(255) NULL"))
                    conn.commit()
                    print("Database migrated: added attachments.stored_filename column")
                except Exception:
                    pass

                # Drop accident_description column if exists
                try:
                    conn.execute(text("ALTER TABLE claims DROP COLUMN accident_description"))
                    conn.commit()
                    print("Database migrated: removed accident_description column")
                except Exception:
                    pass

            print("Database connected and tables verified!")
            return
        except Exception as e:
            print(f"Database connection failed: {e}. Retrying in 5 seconds...")
            retries -= 1
            time.sleep(5)
    raise Exception("Could not connect to database after multiple retries")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

# --- FastAPI App ---
app = FastAPI(title="Insurance Accident Declaration API", lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://insurance.local", "http://frontend.local"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Static Car Data ---
CAR_MODELS = {
    "Peugeot": ["208", "308", "2008", "3008", "5008", "Partner"],
    "Renault": ["Clio", "Megane", "Captur", "Kadjar", "Symbol", "Kangoo"],
    "Volkswagen": ["Golf", "Polo", "Passat", "Tiguan", "Caddy"],
    "Citroen": ["C3", "C4", "C5", "Berlingo"],
    "Dacia": ["Sandero", "Duster", "Logan"],
    "Fiat": ["500", "Panda", "Tipo", "Fiorino"],
    "Toyota": ["Yaris", "Corolla", "Hilux"],
    "Hyundai": ["i10", "i20", "Tucson"],
    "Kia": ["Rio", "Picanto", "Sportage"],
    "BMW": ["Série 1", "Série 3", "Série 5", "X1", "X3", "X5"],
    "Mercedes-Benz": ["Classe A", "Classe C", "Classe E", "GLA", "GLC"],
}

@app.get("/api/car-models")
async def get_car_models():
    return CAR_MODELS

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth helpers ---

def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session")

def require_admin(request: Request) -> str:
    """Dependency for any admin-only route. Validates the JWT from the
    httpOnly cookie on every request - this is the actual security boundary,
    independent of anything the frontend does or doesn't render."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_access_token(token)

def validate_upload(file: UploadFile, header_bytes: bytes) -> None:
    """Reject anything that isn't genuinely PDF/JPG/PNG. Checks extension,
    declared content_type, AND actual magic bytes - all three must agree.
    Any one of these alone is spoofable by the client."""
    original_name = os.path.basename(file.filename or "upload")
    ext = os.path.splitext(original_name)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Extension non autorisée: {ext or '(aucune)'}")

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Type de fichier non autorisé: {file.content_type}")

    signatures = MAGIC_SIGNATURES.get(ext, [])
    if not any(header_bytes.startswith(sig) for sig in signatures):
        raise HTTPException(
            status_code=400,
            detail=f"Le contenu du fichier '{original_name}' ne correspond pas à son extension déclarée",
        )

# --- Auth Routes ---

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.username == payload.username).first()

    # Same generic error whether username doesn't exist or password is wrong -
    # never reveal which one failed.
    invalid_creds = HTTPException(status_code=401, detail="Identifiants invalides")

    if not user or not user.is_active:
        raise invalid_creds
    if not pwd_context.verify(payload.password, user.password_hash):
        raise invalid_creds

    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(user.username)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=JWT_EXPIRE_MINUTES * 60,
        path="/",
    )
    return {"status": "ok", "username": user.username}

@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "ok"}

@app.get("/api/me")
def me(username: str = Depends(require_admin)):
    return {"username": username}

# --- Claim Routes ---

@app.post("/api/claims")
async def create_claim(
    full_name: str = Form(...),
    cin: str = Form(...),
    policy_number: str = Form(...),
    phone_number: str = Form(...),
    vehicle_details: str = Form(...),
    email: Optional[str] = Form(None),
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    # Validate every file BEFORE creating any DB rows or writing anything
    # to disk, so a rejected upload doesn't leave a half-created claim behind.
    headers = []
    for file in files:
        header_bytes = await file.read(8)
        await file.seek(0)
        validate_upload(file, header_bytes)
        headers.append(header_bytes)

    db_claim = Claim(
        full_name=full_name,
        email=email,
        cin=cin,
        policy_number=policy_number,
        phone_number=phone_number,
        vehicle_details=vehicle_details
    )
    db.add(db_claim)
    db.commit()
    db.refresh(db_claim)

    for file in files:
        original_name = os.path.basename(file.filename or "upload")
        unique_filename = f"{db_claim.id}_{uuid.uuid4().hex}_{original_name}"

        final_path = os.path.join(SCAN_INPUT_DIR, unique_filename)
        tmp_path = os.path.join(SCAN_INPUT_DIR, f".tmp.{unique_filename}")

        with open(tmp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Atomic rename so the av-scanner's "stable size across two polls"
        # check never sees a half-written file under its final name.
        os.rename(tmp_path, final_path)

        db_attachment = Attachment(
            claim_id=db_claim.id,
            file_name=file.filename,
            file_path=final_path,        # kept populated for backward compat
            file_type=file.content_type,
            stored_filename=unique_filename
        )
        db.add(db_attachment)
    db.commit()
    return {"message": "Claim submitted successfully", "claim_id": db_claim.id}

@app.get("/api/claims")
async def get_claims(username: str = Depends(require_admin), db: Session = Depends(get_db)):
    claims = db.query(Claim).all()
    result = []
    for claim in claims:
        attachments = []
        for a in claim.attachments:
            if not a.stored_filename:
                continue
            if os.path.isfile(os.path.join(CLEAN_OUTPUT_DIR, a.stored_filename)):
                attachments.append({
                    "id": a.id,
                    "file_name": a.file_name,
                    "download_url": f"/api/attachments/{a.id}/file"
                })
        # attachments not yet clean (still scanning, or rejected) are
        # simply omitted - the admin dashboard sees nothing for them.
        result.append({
            "id": claim.id,
            "full_name": claim.full_name,
            "email": claim.email,
            "cin": claim.cin,
            "policy_number": claim.policy_number,
            "phone_number": claim.phone_number,
            "vehicle_details": claim.vehicle_details,
            "status": claim.status,
            "created_at": claim.created_at,
            "attachments": attachments
        })
    return result

@app.patch("/api/claims/{claim_id}/status")
async def update_claim_status(
    claim_id: int,
    status: str,
    username: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_claim = db.query(Claim).filter(Claim.id == claim_id).first()
    if not db_claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    old_status = db_claim.status
    db_claim.status = status
    db.commit()

    # Send email if status changed and email exists
    if old_status != status and db_claim.email:
        send_status_email(db_claim.email, db_claim.id, db_claim.full_name, status)

    return {"message": "Status updated successfully"}


@app.get("/api/attachments/{attachment_id}/file")
async def download_attachment(
    attachment_id: int,
    username: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    attachment = db.query(Attachment).filter(Attachment.id == attachment_id).first()
    if not attachment or not attachment.stored_filename:
        raise HTTPException(status_code=404, detail="Attachment not found")

    file_path = os.path.join(CLEAN_OUTPUT_DIR, attachment.stored_filename)
    if not os.path.isfile(file_path):
        # Either still being scanned, or was flagged/errored and deleted.
        # Either way: nothing to show. No distinction is surfaced to the caller.
        raise HTTPException(status_code=404, detail="File not available")

    return FileResponse(path=file_path, filename=attachment.file_name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
