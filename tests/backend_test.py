"""BloodLink backend API tests"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://blood-connect-70.preview.emergentagent.com").rstrip("/")
# Read frontend env if env var missing
try:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
except Exception:
    pass

API = f"{BASE_URL}/api"
ADMIN = {"email": "admin@bloodbank.com", "password": "admin123"}

UNIQ = uuid.uuid4().hex[:8]
DONOR = {"email": f"TEST_donor_{UNIQ}@test.com", "password": "Test@123", "name": "Test Donor",
         "role": "donor", "blood_group": "O+", "city": "Mumbai"}
HOSPITAL = {"email": f"TEST_hosp_{UNIQ}@test.com", "password": "Test@123", "name": "Test Hospital",
            "role": "hospital", "city": "Mumbai"}
RECEIVER = {"email": f"TEST_rec_{UNIQ}@test.com", "password": "Test@123", "name": "Test Receiver",
            "role": "receiver", "city": "Mumbai"}

state = {}


def s():
    return requests.Session()


# ---- Auth ----
def test_root():
    r = requests.get(f"{API}/")
    assert r.status_code == 200
    assert "BloodLink" in r.json()["message"]


def test_admin_login():
    r = requests.post(f"{API}/auth/login", json=ADMIN)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "token" in data and data["user"]["role"] == "admin"
    assert "access_token" in r.cookies
    state["admin_token"] = data["token"]
    state["admin_id"] = data["user"]["id"]


def test_login_invalid():
    r = requests.post(f"{API}/auth/login", json={"email": "admin@bloodbank.com", "password": "wrong"})
    assert r.status_code == 401


def test_register_donor():
    r = requests.post(f"{API}/auth/register", json=DONOR)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["user"]["role"] == "donor"
    assert data["user"]["available"] is True
    assert "password_hash" not in data["user"]
    state["donor_token"] = data["token"]
    state["donor_id"] = data["user"]["id"]


def test_register_hospital():
    r = requests.post(f"{API}/auth/register", json=HOSPITAL)
    assert r.status_code == 200
    state["hospital_token"] = r.json()["token"]
    state["hospital_id"] = r.json()["user"]["id"]


def test_register_receiver():
    r = requests.post(f"{API}/auth/register", json=RECEIVER)
    assert r.status_code == 200
    state["receiver_token"] = r.json()["token"]
    state["receiver_id"] = r.json()["user"]["id"]


def test_register_duplicate():
    r = requests.post(f"{API}/auth/register", json=DONOR)
    assert r.status_code == 400


def test_me():
    h = {"Authorization": f"Bearer {state['donor_token']}"}
    r = requests.get(f"{API}/auth/me", headers=h)
    assert r.status_code == 200
    assert r.json()["email"] == DONOR["email"].lower()


def test_me_unauth():
    r = requests.get(f"{API}/auth/me")
    assert r.status_code == 401


def test_logout():
    sess = s()
    sess.post(f"{API}/auth/login", json=ADMIN)
    r = sess.post(f"{API}/auth/logout")
    assert r.status_code == 200
    # cookie should be cleared
    r2 = sess.get(f"{API}/auth/me")
    assert r2.status_code == 401


# ---- Profile ----
def test_profile_update_donor_available():
    h = {"Authorization": f"Bearer {state['donor_token']}"}
    r = requests.put(f"{API}/profile", json={"available": False}, headers=h)
    assert r.status_code == 200
    assert r.json()["available"] is False
    # restore
    requests.put(f"{API}/profile", json={"available": True}, headers=h)


# ---- Donors / Hospitals search ----
def test_list_donors_filter():
    r = requests.get(f"{API}/donors", params={"blood_group": "O+", "city": "mum"})
    assert r.status_code == 200
    emails = [d["email"] for d in r.json()]
    assert DONOR["email"].lower() in emails


def test_list_donors_case_insensitive_city():
    r = requests.get(f"{API}/donors", params={"city": "MUMBAI"})
    assert r.status_code == 200
    emails = [d["email"] for d in r.json()]
    assert DONOR["email"].lower() in emails


# ---- Inventory ----
def test_inventory_update_hospital():
    h = {"Authorization": f"Bearer {state['hospital_token']}"}
    items = [{"blood_group": bg, "units": 10} for bg in ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]]
    r = requests.put(f"{API}/inventory/me", json={"items": items}, headers=h)
    assert r.status_code == 200
    r2 = requests.get(f"{API}/inventory/me", headers=h)
    assert r2.status_code == 200
    assert len(r2.json()) == 8


def test_inventory_role_protection():
    h = {"Authorization": f"Bearer {state['donor_token']}"}
    r = requests.get(f"{API}/inventory/me", headers=h)
    assert r.status_code == 403


def test_list_hospitals_with_inventory():
    r = requests.get(f"{API}/hospitals", params={"blood_group": "O+", "city": "mum"})
    assert r.status_code == 200
    ids = [h["id"] for h in r.json()]
    assert state["hospital_id"] in ids


# ---- Requests ----
def test_create_request_to_hospital():
    h = {"Authorization": f"Bearer {state['receiver_token']}"}
    payload = {"blood_group": "O+", "units": 2, "target_type": "hospital",
               "target_id": state["hospital_id"], "city": "Mumbai"}
    r = requests.post(f"{API}/requests", json=payload, headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "pending"
    state["req_id"] = data["id"]


def test_requests_sent():
    h = {"Authorization": f"Bearer {state['receiver_token']}"}
    r = requests.get(f"{API}/requests/sent", headers=h)
    assert r.status_code == 200
    assert any(x["id"] == state["req_id"] for x in r.json())


def test_requests_received_hospital():
    h = {"Authorization": f"Bearer {state['hospital_token']}"}
    r = requests.get(f"{API}/requests/received", headers=h)
    assert r.status_code == 200
    assert any(x["id"] == state["req_id"] for x in r.json())


def test_respond_unauthorized_user():
    h = {"Authorization": f"Bearer {state['donor_token']}"}
    r = requests.post(f"{API}/requests/{state['req_id']}/respond",
                      json={"status": "approved"}, headers=h)
    assert r.status_code == 403


def test_respond_approve_decrements_inventory():
    h = {"Authorization": f"Bearer {state['hospital_token']}"}
    r = requests.post(f"{API}/requests/{state['req_id']}/respond",
                      json={"status": "approved", "message": "ok"}, headers=h)
    assert r.status_code == 200
    inv = requests.get(f"{API}/inventory/me", headers=h).json()
    op = next(i for i in inv if i["blood_group"] == "O+")
    assert op["units"] == 8  # 10 - 2


# ---- Admin ----
def test_admin_users_list():
    h = {"Authorization": f"Bearer {state['admin_token']}"}
    r = requests.get(f"{API}/admin/users", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list) and len(r.json()) >= 4


def test_admin_role_protection():
    h = {"Authorization": f"Bearer {state['donor_token']}"}
    r = requests.get(f"{API}/admin/users", headers=h)
    assert r.status_code == 403


def test_admin_cannot_delete_self():
    h = {"Authorization": f"Bearer {state['admin_token']}"}
    r = requests.delete(f"{API}/admin/users/{state['admin_id']}", headers=h)
    assert r.status_code == 400


def test_admin_delete_user():
    # delete the donor we created
    h = {"Authorization": f"Bearer {state['admin_token']}"}
    r = requests.delete(f"{API}/admin/users/{state['donor_id']}", headers=h)
    assert r.status_code == 200
    # cleanup remaining test users
    requests.delete(f"{API}/admin/users/{state['hospital_id']}", headers=h)
    requests.delete(f"{API}/admin/users/{state['receiver_id']}", headers=h)


# ---- Analytics ----
def test_analytics_overview():
    r = requests.get(f"{API}/analytics/overview")
    assert r.status_code == 200
    data = r.json()
    for key in ["totals", "demand", "donor_distribution", "inventory"]:
        assert key in data
    assert len(data["demand"]) == 8
    assert len(data["donor_distribution"]) == 8
    assert len(data["inventory"]) == 8
