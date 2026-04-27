from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import uuid
import logging
import bcrypt
import jwt
import asyncio
import resend
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Literal

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict


# ---- DB ----
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

JWT_ALGORITHM = "HS256"
BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
Role = Literal["donor", "receiver", "hospital", "admin"]

# ---- Email (Resend) ----
resend.api_key = os.environ.get("RESEND_API_KEY", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")


async def send_email(to: str, subject: str, html: str):
    if not resend.api_key or not to:
        return None
    params = {"from": SENDER_EMAIL, "to": [to], "subject": subject, "html": html}
    try:
        return await asyncio.to_thread(resend.Emails.send, params)
    except Exception as e:
        logging.getLogger("bloodbank").warning(f"Resend failed: {e}")
        return None


def request_email_html(title: str, body: str, cta: str = "") -> str:
    return f"""
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:0 auto;padding:28px;background:#ffffff;border:1px solid #e9e6e0;border-radius:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <div style="width:32px;height:32px;border-radius:8px;background:#c8102e;color:white;display:inline-flex;align-items:center;justify-content:center;font-weight:700">B</div>
        <div style="font-weight:700;font-size:18px;letter-spacing:-0.02em">BloodLink</div>
      </div>
      <h1 style="font-size:26px;font-weight:800;margin:0 0 12px 0;letter-spacing:-0.02em">{title}</h1>
      <p style="color:#4b5563;line-height:1.6;margin:0 0 16px 0">{body}</p>
      {cta}
      <hr style="border:none;border-top:1px dashed #e9e6e0;margin:24px 0" />
      <p style="color:#9ca3af;font-size:12px;margin:0">Sent from BloodLink · a drop saves a life</p>
    </div>
    """


# ---- Helpers ----
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "access",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def serialize(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    doc.pop("password_hash", None)
    return doc


# ---- Models ----
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str
    role: Role
    phone: Optional[str] = None
    blood_group: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    role: str
    phone: Optional[str] = None
    blood_group: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    available: Optional[bool] = True
    created_at: Optional[str] = None


class DonorProfileIn(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    blood_group: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    available: Optional[bool] = None
    last_donation_date: Optional[str] = None


class HospitalProfileIn(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None


class InventoryItem(BaseModel):
    blood_group: str
    units: int = Field(ge=0)


class InventoryUpdateIn(BaseModel):
    items: List[InventoryItem]


class BloodRequestIn(BaseModel):
    blood_group: str
    units: int = Field(ge=1)
    city: Optional[str] = None
    notes: Optional[str] = None
    target_type: Literal["hospital", "donor"]
    target_id: str  # user_id of hospital or donor


class RequestRespondIn(BaseModel):
    status: Literal["approved", "rejected"]
    message: Optional[str] = None


class BloodDriveIn(BaseModel):
    title: str
    description: Optional[str] = None
    date: str  # ISO date string
    time: Optional[str] = None
    city: str
    address: Optional[str] = None
    blood_groups_needed: List[str] = Field(default_factory=list)


# ---- App ----
app = FastAPI(title="BloodLink API")
api = APIRouter(prefix="/api")


# ---- Auth dependency ----
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return serialize(user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(*roles: str):
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _dep


def set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )


# ---- Auth routes ----
@api.post("/auth/register")
async def register(payload: RegisterIn, response: Response):
    email = payload.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(payload.password),
        "name": payload.name,
        "role": payload.role,
        "phone": payload.phone,
        "blood_group": payload.blood_group,
        "city": payload.city,
        "address": payload.address,
        "available": True if payload.role == "donor" else None,
        "created_at": now_iso(),
    }
    await db.users.insert_one(doc)
    token = create_access_token(user_id, email, payload.role)
    set_auth_cookie(response, token)
    return {"user": serialize({**doc}), "token": token}


@api.post("/auth/login")
async def login(payload: LoginIn, response: Response):
    email = payload.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user["id"], email, user["role"])
    set_auth_cookie(response, token)
    return {"user": serialize({**user}), "token": token}


@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# ---- Profile routes ----
@api.put("/profile")
async def update_profile(payload: DonorProfileIn, user: dict = Depends(get_current_user)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update:
        return user
    await db.users.update_one({"id": user["id"]}, {"$set": update})
    updated = await db.users.find_one({"id": user["id"]})
    return serialize(updated)


# ---- Donor search ----
@api.get("/donors")
async def list_donors(blood_group: Optional[str] = None, city: Optional[str] = None):
    query: dict = {"role": "donor", "available": True}
    if blood_group:
        query["blood_group"] = blood_group
    if city:
        query["city"] = {"$regex": f"^{city}", "$options": "i"}
    cursor = db.users.find(query, {"_id": 0, "password_hash": 0}).limit(200)
    return await cursor.to_list(200)


# ---- Hospital search & inventory ----
@api.get("/hospitals")
async def list_hospitals(blood_group: Optional[str] = None, city: Optional[str] = None):
    query: dict = {"role": "hospital"}
    if city:
        query["city"] = {"$regex": f"^{city}", "$options": "i"}
    cursor = db.users.find(query, {"_id": 0, "password_hash": 0}).limit(200)
    hospitals = await cursor.to_list(200)
    # attach inventory
    for h in hospitals:
        inv = await db.inventories.find_one({"hospital_id": h["id"]}, {"_id": 0})
        h["inventory"] = inv["items"] if inv else []
    if blood_group:
        hospitals = [h for h in hospitals if any(i["blood_group"] == blood_group and i["units"] > 0 for i in h["inventory"])]
    return hospitals


@api.get("/inventory/me")
async def get_my_inventory(user: dict = Depends(require_role("hospital"))):
    inv = await db.inventories.find_one({"hospital_id": user["id"]}, {"_id": 0})
    return inv["items"] if inv else []


@api.put("/inventory/me")
async def update_my_inventory(payload: InventoryUpdateIn, user: dict = Depends(require_role("hospital"))):
    items = [i.model_dump() for i in payload.items]
    await db.inventories.update_one(
        {"hospital_id": user["id"]},
        {"$set": {"hospital_id": user["id"], "items": items, "updated_at": now_iso()}},
        upsert=True,
    )
    return items


# ---- Blood requests ----
@api.post("/requests")
async def create_request(payload: BloodRequestIn, user: dict = Depends(get_current_user)):
    req_id = str(uuid.uuid4())
    doc = {
        "id": req_id,
        "requester_id": user["id"],
        "requester_name": user["name"],
        "requester_email": user["email"],
        "blood_group": payload.blood_group,
        "units": payload.units,
        "city": payload.city or user.get("city"),
        "notes": payload.notes,
        "target_type": payload.target_type,
        "target_id": payload.target_id,
        "status": "pending",
        "response_message": None,
        "created_at": now_iso(),
    }
    await db.requests.insert_one(doc)
    # MOCKED email notification - logs to console
    logger.info(f"[EMAIL-MOCKED] New blood request from {user['email']} to target {payload.target_id}")
    return serialize({**doc})


@api.get("/requests/sent")
async def my_sent_requests(user: dict = Depends(get_current_user)):
    cursor = db.requests.find({"requester_id": user["id"]}, {"_id": 0}).sort("created_at", -1)
    return await cursor.to_list(200)


@api.get("/requests/received")
async def my_received_requests(user: dict = Depends(get_current_user)):
    cursor = db.requests.find({"target_id": user["id"]}, {"_id": 0}).sort("created_at", -1)
    return await cursor.to_list(200)


@api.post("/requests/{request_id}/respond")
async def respond_request(request_id: str, payload: RequestRespondIn, user: dict = Depends(get_current_user)):
    req = await db.requests.find_one({"id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    if req["target_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    update = {"status": payload.status, "response_message": payload.message, "responded_at": now_iso()}
    await db.requests.update_one({"id": request_id}, {"$set": update})
    # If hospital approves, decrement inventory
    if payload.status == "approved" and req["target_type"] == "hospital":
        inv = await db.inventories.find_one({"hospital_id": user["id"]})
        if inv:
            items = inv["items"]
            for it in items:
                if it["blood_group"] == req["blood_group"]:
                    it["units"] = max(0, it["units"] - req["units"])
            await db.inventories.update_one({"hospital_id": user["id"]}, {"$set": {"items": items}})
    logger.info(f"Request {request_id} {payload.status} by {user['email']}")
    # Notify requester via Resend
    await send_email(
        req["requester_email"],
        f"Your blood request was {payload.status}",
        request_email_html(
            f"Request {payload.status}",
            f"Your request for <b>{req['units']} unit(s)</b> of <b>{req['blood_group']}</b> was <b>{payload.status}</b> by <b>{user['name']}</b>.<br/><br/>{('Message: ' + payload.message) if payload.message else ''}",
        ),
    )
    return {"ok": True, "status": payload.status}


# ---- Admin ----
@api.get("/admin/users")
async def admin_users(user: dict = Depends(require_role("admin"))):
    cursor = db.users.find({}, {"_id": 0, "password_hash": 0}).sort("created_at", -1)
    return await cursor.to_list(1000)


@api.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, user: dict = Depends(require_role("admin"))):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete self")
    await db.users.delete_one({"id": user_id})
    return {"ok": True}


@api.get("/admin/requests")
async def admin_requests(user: dict = Depends(require_role("admin"))):
    cursor = db.requests.find({}, {"_id": 0}).sort("created_at", -1)
    return await cursor.to_list(1000)


# ---- Analytics ----
# ---- Blood Drives ----
@api.get("/drives")
async def list_drives(city: Optional[str] = None, blood_group: Optional[str] = None):
    query: dict = {}
    if city:
        query["city"] = {"$regex": f"^{city}", "$options": "i"}
    if blood_group:
        query["blood_groups_needed"] = blood_group
    cursor = db.drives.find(query, {"_id": 0}).sort("date", 1)
    return await cursor.to_list(500)


@api.post("/drives")
async def create_drive(payload: BloodDriveIn, user: dict = Depends(require_role("hospital"))):
    drive_id = str(uuid.uuid4())
    doc = {
        "id": drive_id,
        "hospital_id": user["id"],
        "hospital_name": user["name"],
        "title": payload.title,
        "description": payload.description,
        "date": payload.date,
        "time": payload.time,
        "city": payload.city,
        "address": payload.address,
        "blood_groups_needed": payload.blood_groups_needed,
        "created_at": now_iso(),
    }
    await db.drives.insert_one(doc)

    # Notify matching donors (same city prefix + any of needed blood groups)
    donor_query: dict = {"role": "donor", "available": True}
    if payload.blood_groups_needed:
        donor_query["blood_group"] = {"$in": payload.blood_groups_needed}
    if payload.city:
        donor_query["city"] = {"$regex": f"^{payload.city}", "$options": "i"}
    cursor = db.users.find(donor_query, {"_id": 0, "password_hash": 0}).limit(200)
    donors = await cursor.to_list(200)

    subject = f"Blood drive near you · {payload.title}"
    for d in donors:
        if not d.get("email"):
            continue
        body = (
            f"<b>{user['name']}</b> is hosting a blood drive on <b>{payload.date}"
            f"{(' at ' + payload.time) if payload.time else ''}</b> in <b>{payload.city}</b>."
            f"<br/><br/>{payload.description or ''}"
            f"<br/><br/>Blood groups needed: <b>{', '.join(payload.blood_groups_needed) or 'All'}</b>"
            f"<br/>Address: {payload.address or '—'}"
        )
        await send_email(d["email"], subject, request_email_html(f"You're invited: {payload.title}", body))

    logger.info(f"Drive {drive_id} created by {user['email']} · notified {len(donors)} donors")
    return {**serialize({**doc}), "notified_donors": len(donors)}


@api.delete("/drives/{drive_id}")
async def delete_drive(drive_id: str, user: dict = Depends(get_current_user)):
    drive = await db.drives.find_one({"id": drive_id})
    if not drive:
        raise HTTPException(status_code=404, detail="Drive not found")
    if drive["hospital_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    await db.drives.delete_one({"id": drive_id})
    return {"ok": True}


@api.get("/drives/mine")
async def my_drives(user: dict = Depends(require_role("hospital"))):
    cursor = db.drives.find({"hospital_id": user["id"]}, {"_id": 0}).sort("date", 1)
    return await cursor.to_list(500)


@api.get("/analytics/overview")
async def analytics_overview():
    total_donors = await db.users.count_documents({"role": "donor"})
    total_hospitals = await db.users.count_documents({"role": "hospital"})
    total_receivers = await db.users.count_documents({"role": "receiver"})
    total_requests = await db.requests.count_documents({})
    pending = await db.requests.count_documents({"status": "pending"})
    approved = await db.requests.count_documents({"status": "approved"})
    # blood group demand from requests
    demand = {bg: 0 for bg in BLOOD_GROUPS}
    async for r in db.requests.find({}, {"_id": 0, "blood_group": 1, "units": 1}):
        if r["blood_group"] in demand:
            demand[r["blood_group"]] += r.get("units", 0)
    # donor distribution
    donor_dist = {bg: 0 for bg in BLOOD_GROUPS}
    async for u in db.users.find({"role": "donor"}, {"_id": 0, "blood_group": 1}):
        if u.get("blood_group") in donor_dist:
            donor_dist[u["blood_group"]] += 1
    # total inventory across hospitals
    inv_total = {bg: 0 for bg in BLOOD_GROUPS}
    async for inv in db.inventories.find({}, {"_id": 0}):
        for it in inv.get("items", []):
            if it["blood_group"] in inv_total:
                inv_total[it["blood_group"]] += it["units"]
    return {
        "totals": {
            "donors": total_donors,
            "hospitals": total_hospitals,
            "receivers": total_receivers,
            "requests": total_requests,
            "pending": pending,
            "approved": approved,
        },
        "demand": [{"blood_group": k, "units": v} for k, v in demand.items()],
        "donor_distribution": [{"blood_group": k, "count": v} for k, v in donor_dist.items()],
        "inventory": [{"blood_group": k, "units": v} for k, v in inv_total.items()],
    }


@api.get("/")
async def root():
    return {"message": "BloodLink API", "status": "ok"}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("bloodbank")


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.requests.create_index("requester_id")
    await db.requests.create_index("target_id")
    await db.inventories.create_index("hospital_id", unique=True)
    await db.drives.create_index("date")
    await db.drives.create_index("city")
    # seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@bloodbank.com").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "Admin",
            "role": "admin",
            "created_at": now_iso(),
        })
        logger.info(f"Seeded admin: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password)}},
        )


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
