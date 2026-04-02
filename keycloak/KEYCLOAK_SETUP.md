# Keycloak Setup Guide for SpanTag

## Step 1 — Download & Start Keycloak (no Docker)

Download Keycloak 26.x from https://www.keycloak.org/downloads

```bash
# Windows
cd C:\keycloak-26.x.x\bin
kc.bat start-dev --http-port=8180

# Linux / Mac
cd ~/keycloak-26.x.x/bin
./kc.sh start-dev --http-port=8180
```

Keycloak runs on **http://localhost:8180**

## Step 2 — Create Admin Account

On first start, go to http://localhost:8180 and create an admin account.
Default: admin / admin

## Step 3 — Import the SpanTag Realm

Option A — Import via UI:
1. Open http://localhost:8180/admin
2. Hover over "master" realm (top-left) → click "Create Realm"
3. Click "Browse" → select `spantag-realm.json` from this folder
4. Click "Create"

Option B — Import via CLI:
```bash
# Windows
kc.bat import --file=C:\path\to\spantag-realm.json

# Linux
./kc.sh import --file=/path/to/spantag-realm.json
```

## Step 4 — Configure spantag-admin client secret

1. Open Keycloak Admin → Realm: spantag → Clients → spantag-admin
2. Go to "Credentials" tab
3. Click "Regenerate Secret" — copy the value
4. Set it as env variable before starting auth-service:
   ```
   Windows: set KEYCLOAK_ADMIN_SECRET=paste-secret-here
   Linux:   export KEYCLOAK_ADMIN_SECRET=paste-secret-here
   ```

## Step 5 — Assign Service Account Roles for spantag-admin

This allows spantag-admin to create/manage users via API.

1. Clients → spantag-admin → Service accounts roles tab
2. Click "Assign role" → Filter by "realm-management"
3. Assign: manage-users, view-users, manage-clients

## Step 6 — Enable Direct Grant for spantag-app

1. Clients → spantag-app → Settings
2. Set "Direct access grants" → ON
3. Save

## Step 7 — Add Role Mapper to spantag-app (for realm_access in JWT)

The gateway reads `realm_access.roles` from the JWT.
This is enabled by default in Keycloak — no extra config needed.

## Step 8 — Create Test Users (optional — or use /api/auth/register)

1. Realm: spantag → Users → Add user
2. Fill username, email, save
3. Credentials tab → Set password → Temporary OFF
4. Role mappings → Assign "user" or "admin"

## Service Startup Order

```
1. Keycloak    :8180   ← MUST be running first
2. Auth        :9090
3. Profile     :9093
4. User        :9091
5. Dashboard   :9094
6. Payment     :9096
7. Order       :9095
8. OAuth2      :9092
9. Gateway     :1013   ← last
```
