## Auth Service – Module 2 (Authentication System)

This service provides staff authentication for the WhatsApp Package Notification System.
The current implementation covers **Module 2** of the Waterfall system design.

### Environment configuration

The service expects the following environment variables (e.g. via a `.env` file):

- **DB_USER**: PostgreSQL username
- **DB_PASSWORD**: PostgreSQL password
- **DB_HOST**: PostgreSQL host
- **DB_PORT**: PostgreSQL port
- **DB_DATABASE**: PostgreSQL database name
- **JWT_SECRET**: Secret key for signing JWT access tokens
- **JWT_EXPIRES_IN** (optional): Access token lifetime, e.g. `30m`
- **PORT** (optional): HTTP port (defaults to `3000`)

### Running the service

- **Install dependencies**: `npm install`
- **Development** (with reload): `npm run dev`
- **Production**: `npm run start`

Once running, the service exposes the following endpoints.

### Health check

- **GET `/health`**
  - **Purpose**: Simple liveness/health probe.
  - **Response**: `200 OK` with JSON `{ status, service, time }`.

---

### Module 2.1 – Staff Registration

- **POST `/api/auth/register`**
  - **Purpose**: Bootstrap creation of initial staff accounts (e.g. first Admin / Operators).
  - **Security note**: In production this route should be restricted to Admins or disabled once initial staff have been created.
  - **Request body (JSON)**:
    - `username` (string, required, 3–50 chars)
    - `password` (string, required, at least 8 chars)
    - `role` (string, required: one of `Admin`, `Operator`, `Viewer`)
  - **Behaviour**:
    - Validates presence and basic format of `username` and `password`.
    - Ensures `role` is one of the allowed values.
    - Hashes `password` with bcrypt and inserts a new row into the `users` table.
  - **Responses**:
    - `201 Created`: staff user registered; returns `user_id`, `username`, `role`, `created_at`.
    - `400 Bad Request`: missing or invalid `username`, `password`, or `role`.
    - `409 Conflict`: username already exists.
    - `500 Internal Server Error`: unexpected error during registration.

---

### Module 2.2 – Staff Login (JWT Issuance)

- **POST `/api/auth/login`**
  - **Purpose**: Authenticate staff using username and password, returning a JWT access token.
  - **Request body (JSON)**:
    - `username` (string, required)
    - `password` (string, required)
  - **Behaviour**:
    - Looks up the user by `username`.
    - Compares the supplied password with the stored `password_hash` using bcrypt.
    - On success, issues a signed JWT containing `user_id`, `username`, and `role`.
  - **Responses**:
    - `200 OK`: returns `accessToken` and `user` details.
    - `400 Bad Request`: missing `username` or `password`.
    - `401 Unauthorized`: invalid username or password (generic message, no user‑existence leak).
    - `500 Internal Server Error`: unexpected error during login.

---

### Module 2.3 – Auth Middleware & Role-Based Authorization

Module 2 introduces two key helpers used internally in the service:

- **`authenticateToken` middleware**
  - Reads the `Authorization` header (expects `Bearer <token>`).
  - Verifies the JWT using `JWT_SECRET`.
  - On success, attaches the decoded user payload to `req.user`.
  - On failure, returns:
    - `401 Unauthorized` if the token is missing.
    - `403 Forbidden` if the token is invalid or expired.

- **`authorizeRoles(...roles)` middleware**
  - Checks `req.user.role` against an allowed list for the route.
  - Returns `403 Forbidden` if the user’s role is not permitted.

#### Example protected endpoint

- **GET `/api/auth/me`**
  - **Middleware**: `authenticateToken`
  - **Purpose**: Return the currently authenticated user’s JWT payload.
  - **Response**:
    - `200 OK` with `{ user: { user_id, username, role, ... } }` from the token.
    - Standard auth error codes from the middleware on failure.

---

### Module 2.4 – Password Change

- **POST `/api/auth/change-password`**
  - **Middleware**: `authenticateToken`
  - **Purpose**: Allow an authenticated staff member to change their own password.
  - **Request body (JSON)**:
    - `currentPassword` (string, required)
    - `newPassword` (string, required; at least 8 chars)
  - **Behaviour**:
    - Loads the current user by `user_id` from the JWT.
    - Verifies `currentPassword` against the stored `password_hash`.
    - Hashes `newPassword` and updates the `users` table.
  - **Responses**:
    - `200 OK`: password changed successfully.
    - `400 Bad Request`: missing fields or weak new password.
    - `401 Unauthorized`: current password incorrect.
    - `404 Not Found`: user not found for the ID in the token.
    - `500 Internal Server Error`: unexpected error during update.

---

### Current position in the development process

According to the Waterfall‑based system module design, this codebase is now at the end of **Module 2 (Authentication System)** with:

- Staff registration implemented and validated.
- Staff login implemented with JWT‑based session tokens.
- Authentication and authorization middleware ready for reuse by other modules.
- Password change for authenticated staff in place.

The next development steps, outside this service, are to integrate these auth endpoints and middleware into the remaining system modules (e.g., package management, notification sending) according to the overall design.


