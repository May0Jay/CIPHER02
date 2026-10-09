import os, tempfile
os.environ["DB_PATH"] = tempfile.mktemp(suffix=".db"); os.environ["DEV_MODE"] = "1"; os.environ["JWT_SECRET"] = "t"
import app as A, time
c = A.app.test_client()
def post(p, j, tok=None): return c.post(p, json=j, headers={"Authorization": f"Bearer {tok}"} if tok else {})
r = post("/api/auth/signup", {"name": "Jane Doe", "email": "Jane@x.com", "password": "Passw0rd!", "confirmPassword": "nope"}); assert r.status_code == 400
r = post("/api/auth/signup", {"name": "Jane Doe", "email": "Jane@x.com", "password": "Passw0rd!", "confirmPassword": "Passw0rd!"}); assert r.status_code == 201; code = r.json["devCode"]
assert post("/api/auth/verify-otp", {"email": "jane@x.com", "purpose": "signup", "code": "000000"}).status_code == 400
r = post("/api/auth/verify-otp", {"email": "jane@x.com", "purpose": "signup", "code": code}); assert r.status_code == 200; tok = r.json["token"]
assert c.get("/api/dashboard").status_code == 401
d = c.get("/api/dashboard", headers={"Authorization": f"Bearer {tok}"}).json; assert d["stats"]["openAlerts"] == 5 and d["activeIncident"]["id"] == "INC-2041"
assert post("/api/incidents/INC-2041/action", {"action": "block"}, tok).json["status"] == "blocked"
L = c.get("/api/incidents?severity=critical", headers={"Authorization": f"Bearer {tok}"}).json
assert {i["id"] for i in L["incidents"]} == {"INC-2041", "INC-2036"} and L["counts"]["all"] == 8
assert c.get("/api/incidents?q=verma", headers={"Authorization": f"Bearer {tok}"}).json["incidents"][0]["id"] == "INC-2041"
assert post("/api/incidents/INC-2040/action", {"action": "resolve"}, tok).json["status"] == "resolved"
D = c.get("/api/incidents/INC-2040", headers={"Authorization": f"Bearer {tok}"}).json; assert D["incident"]["status"] == "resolved" and D["history"][0]["action"] == "resolve"
assert c.get("/api/incidents/NOPE", headers={"Authorization": f"Bearer {tok}"}).status_code == 404
assert post("/api/auth/signin", {"email": "jane@x.com", "password": "wrong"}).status_code == 401
r = post("/api/auth/signin", {"email": "jane@x.com", "password": "Passw0rd!"}); assert r.json["purpose"] == "signin"
assert post("/api/auth/resend-otp", {"email": "jane@x.com", "purpose": "signin"}).status_code == 429
assert post("/api/auth/signout", {}, tok).status_code == 200
assert c.get("/api/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
r = post("/api/auth/forgot-password", {"email": "jane@x.com"}); code = r.json["devCode"]
rt = post("/api/auth/verify-otp", {"email": "jane@x.com", "purpose": "reset", "code": code}).json["resetToken"]
assert post("/api/auth/reset-password", {"resetToken": rt, "password": "NewPassw0rd!", "confirmPassword": "NewPassw0rd!"}).status_code == 200
import sqlite3; q = sqlite3.connect(os.environ["DB_PATH"]); q.execute("DELETE FROM otps"); q.commit()  # skip the 30s resend cooldown
assert post("/api/auth/signin", {"email": "jane@x.com", "password": "NewPassw0rd!"}).status_code == 200
assert post("/api/auth/signin", {"email": "jane@x.com", "password": "Passw0rd!"}).status_code == 401  # old password rejected

# ---- employees / endpoints / history / extension events ----

import sqlite3; q = sqlite3.connect(os.environ["DB_PATH"]); q.execute("DELETE FROM otps"); q.commit()
r = post("/api/auth/signin", {"email": "jane@x.com", "password": "NewPassw0rd!"}); code = r.json["devCode"]
tok = post("/api/auth/verify-otp", {"email": "jane@x.com", "purpose": "signin", "code": code}).json["token"]
B = c.get("/api/bootstrap", headers={"Authorization": f"Bearer {tok}"}).json
assert len(B["alerts"]) == 8 and len(B["employees"]) == 12 and len(B["endpoints"]) == 14 and len(B["history"]) >= 15
assert post("/api/employees/D. Sethi/action", {"action": "watch"}, tok).json["message"] == "Removed from watchlist"
assert post("/api/endpoints/WS-0233/action", {"action": "usb"}, tok).json["message"] == "USB storage blocked"
assert post("/api/endpoints/WS-0319/action", {"action": "iso"}, tok).status_code == 400   # offline
assert post("/api/endpoints/WS-0275/action", {"action": "upd"}, tok).json["message"].startswith("Agent updated")
assert post("/api/incidents/INC-2039/action", {"action": "block"}, tok).json["status"] == "blocked"
assert post("/api/incidents/INC-2037/action", {"action": "block"}, tok).json["status"] == "blocked"
B = c.get("/api/bootstrap", headers={"Authorization": f"Bearer {tok}"}).json
assert {e["host"]: e["st"] for e in B["endpoints"]}["WS-0150"] == "isolated"      # blocking an alert isolates its device
assert B["history"][0]["cat"] in ("alert", "endpoint") and B["history"][0]["by"] == "Jane Doe"
r = post("/api/events", {"kind": "upload", "domain": "wetransfer.com", "files": [{"name": "a.xlsx", "size": 5000000}] * 6}, tok).json
assert r["recorded"] and r["score"] >= 80, r
r2 = post("/api/events", {"kind": "upload", "domain": "wetransfer.com", "files": [{"name": "b.pdf", "size": 10}]}, tok).json
assert r2["merged"] and r2["id"] == r["id"]
assert post("/api/events", {"kind": "upload", "domain": "bad domain!", "files": [{"name": "x", "size": 1}]}, tok).status_code == 400
assert post("/api/events", {"kind": "upload", "domain": "x.com", "files": [{"name": "x", "size": 1}]}).status_code == 401
B = c.get("/api/bootstrap", headers={"Authorization": f"Bearer {tok}"}).json
a = [x for x in B["alerts"] if x["id"] == r["id"]][0]; assert a["emp"] == "Jane Doe" and a["path"][1] == "Browser extension" and a["files"] == 7
print("ALL TESTS PASSED")
