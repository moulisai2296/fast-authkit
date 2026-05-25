# AuthKit API Documentation

All authentication, user, and admin endpoints.

---

## Endpoint Index

### Public / User Endpoints (prefix: `/auth`)
1. [Register User](#1-register-user) (`POST /auth/register`)
2. [Login User](#2-login-user) (`POST /auth/login`)
3. [Token Refresh Rotation](#3-token-refresh-rotation) (`POST /auth/refresh`)
4. [Logout Single Session](#4-logout-single-session) (`POST /auth/logout`)
5. [Logout All Devices](#5-logout-all-devices) (`POST /auth/logout-all`)
6. [Get Current User Profile](#6-get-current-user-profile) (`GET /auth/me`)
7. [Forgot Password Request](#7-forgot-password-request) (`POST /auth/forgot-password`)
8. [Reset Password Form Submit](#8-reset-password-form-submit) (`POST /auth/reset-password`)

### Admin Endpoints (prefix: `/admin`)
9. [Admin Dashboard HTML View](#9-admin-dashboard-html-view) (`GET /admin/dashboard`)
10. [Admin System Audit Logs View](#10-admin-system-audit-logs-view) (`GET /admin/audit-logs`)
11. [AJAX: Toggle User Account Status](#11-ajax-toggle-user-account-status) (`POST /admin/users/{user_id}/toggle-active`)
12. [AJAX: Change User Role](#12-ajax-change-user-role) (`POST /admin/users/{user_id}/change-role`)
13. [AJAX: Terminate User Device Session](#13-ajax-terminate-user-device-session) (`POST /admin/sessions/{session_id}/revoke`)
14. [AJAX: Delete User Account](#14-ajax-delete-user-account) (`POST /admin/users/{user_id}/delete`)

---

## 1. Register User

Register a new user account. Registration can be toggled off in `AuthKitConfig` using `enable_register=False`.

*   **URL:** `/auth/register`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "email": "user@example.com",
      "password": "strongpassword123"
    }
    ```
*   **Response (201 Created):**
    ```json
    {
      "id": "7832626e-443b-410a-b286-9040375e8ef8",
      "email": "user@example.com",
      "role": "user",
      "is_active": true,
      "is_verified": false,
      "created_at": "2026-05-25T10:00:00Z",
      "updated_at": "2026-05-25T10:00:00Z"
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: If email already exists or password is less than 8 characters.
    *   `403 Forbidden`: If registration is disabled.

---

## 2. Login User

Authenticate credentials. Generates double tokens: access token (short lived) and refresh token (long lived). Tokens are returned in both the JSON payload (for mobile/API clients) and written to HTTP-only cookies (for browsers).

*   **URL:** `/auth/login`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "email": "user@example.com",
      "password": "strongpassword123"
    }
    ```
*   **Headers Set (Cookies):**
    *   `Set-Cookie`: `authkit_access=<access_token>; HttpOnly; Path=/; SameSite=Lax`
    *   `Set-Cookie`: `authkit_refresh=<refresh_token>; HttpOnly; Path=/; SameSite=Lax`
*   **Response (200 OK):**
    ```json
    {
      "access_token": "ey...",
      "refresh_token": "ey...",
      "token_type": "bearer"
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Incorrect email or password.
    *   `403 Forbidden`: Account is deactivated/banned.

---

## 3. Token Refresh Rotation

Exchange a valid refresh token for a new access token and rotated refresh token. The old refresh token is marked as revoked in the database, preventing reuse.

*   **URL:** `/auth/refresh`
*   **Method:** `POST`
*   **Authorization:** Reads cookie `authkit_refresh` OR checks `Authorization: Bearer <refresh_token>` header.
*   **Headers Set (Cookies):**
    *   `Set-Cookie`: New `authkit_access` and `authkit_refresh` values.
*   **Response (200 OK):**
    ```json
    {
      "access_token": "ey...",
      "refresh_token": "ey...",
      "token_type": "bearer"
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Refresh token is missing, expired, or has been revoked (session terminated).

---

## 4. Logout Single Session

Terminate the current device session, revoke the active refresh token in the database, and clear cookies.

*   **URL:** `/auth/logout`
*   **Method:** `POST`
*   **Authorization:** Reads cookie `authkit_refresh` or `Authorization: Bearer <refresh_token>` header.
*   **Headers Set (Cookies):**
    *   Deletes `authkit_access` and `authkit_refresh` cookies.
*   **Response (200 OK):**
    ```json
    {
      "message": "Successfully logged out."
    }
    ```

---

## 5. Logout All Devices

Revoke *all* active refresh tokens/sessions in the database associated with the logged-in user and clear local cookies. Useful if a user changes their password or suspects account theft.

*   **URL:** `/auth/logout-all`
*   **Method:** `POST`
*   **Authorization:** Requires valid active access token (Cookie or Bearer Header).
*   **Headers Set (Cookies):**
    *   Deletes `authkit_access` and `authkit_refresh` cookies.
*   **Response (200 OK):**
    ```json
    {
      "message": "Successfully logged out of all devices."
    }
    ```

---

## 6. Get Current User Profile

Fetch the profile structure of the active user.

*   **URL:** `/auth/me`
*   **Method:** `GET`
*   **Authorization:** Requires valid active access token.
*   **Response (200 OK):**
    ```json
    {
      "id": "7832626e-443b-410a-b286-9040375e8ef8",
      "email": "user@example.com",
      "role": "user",
      "is_active": true,
      "is_verified": false,
      "created_at": "2026-05-25T10:00:00Z",
      "updated_at": "2026-05-25T10:00:00Z"
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Access token is missing or expired.
    *   `403 Forbidden`: Account is inactive.

---

## 7. Forgot Password Request

Request a password reset link. Generates a short-lived (15 minutes) password reset token and fires the email service.

*   **URL:** `/auth/forgot-password`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "email": "user@example.com"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "If the email is registered, a password reset link has been sent."
    }
    ```
    *Note: Returns a generic success message even if the email does not exist to prevent account enumeration attacks.*

---

## 8. Reset Password Form Submit

Set a new password using a valid reset token generated by `/forgot-password`. Revokes all current active sessions for the user to secure the account.

*   **URL:** `/auth/reset-password`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "token": "<reset_token>",
      "new_password": "newstrongpassword456"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "Password successfully reset. Active sessions have been logged out."
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: Token is invalid or expired.

---

## 9. Admin Dashboard HTML View

Renders the visual administration dashboard showing aggregate user metrics, a listing of all users, and a listing of all active device sessions.

*   **URL:** `/admin/dashboard`
*   **Method:** `GET`
*   **Authorization:** Requires an active cookie token (`authkit_access`) belonging to a user with the `"admin"` role.
*   **Response (200 OK - text/html):** Returns the HTML dashboard page. If unauthorized, redirects (`303 See Other`) to `/admin/login`.

---

## 10. Admin System Audit Logs View

Renders the visual audit logs listing page showing action history, client IPs, user agents, and metadata payloads.

*   **URL:** `/admin/audit-logs`
*   **Method:** `GET`
*   **Authorization:** Requires an active cookie token belonging to an administrator.
*   **Response (200 OK - text/html):** Returns the HTML audit log list view page.

---

## 11. AJAX: Toggle User Account Status

Enables administrators to activate or deactivate user accounts. Deactivating a user immediately revokes all their active device sessions, logging them out everywhere.

*   **URL:** `/admin/users/{user_id}/toggle-active`
*   **Method:** `POST`
*   **Authorization:** Requires active cookie token belonging to an administrator.
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "is_active": false
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "success": true
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: If trying to deactivate yourself.
    *   `403 Forbidden`: Unauthorized admin access.
    *   `404 Not Found`: Target user ID does not exist.

---

## 12. AJAX: Change User Role

Enables administrators to change any user's system role (e.g. from `"user"` to `"admin"` or `"moderator"`).

*   **URL:** `/admin/users/{user_id}/change-role`
*   **Method:** `POST`
*   **Authorization:** Requires active cookie token belonging to an administrator.
*   **Content-Type:** `application/json`
*   **Request Body:**
    ```json
    {
      "role": "admin"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "success": true
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: If trying to change/demote your own administrator role.
    *   `403 Forbidden`: Unauthorized admin access.
    *   `404 Not Found`: Target user ID does not exist.

---

## 13. AJAX: Terminate User Device Session

Enables administrators to force-logout any user device by revoking its specific active database session record.

*   **URL:** `/admin/sessions/{session_id}/revoke`
*   **Method:** `POST`
*   **Authorization:** Requires active cookie token belonging to an administrator.
*   **Response (200 OK):**
    ```json
    {
      "success": true
    }
    ```
*   **Errors:**
    *   `403 Forbidden`: Unauthorized admin access.
    *   `404 Not Found`: Session ID does not exist.

---

## 14. AJAX: Delete User Account

Permanently purge a user's account from the database. This cascades and deletes all associated sessions and logs.

*   **URL:** `/admin/users/{user_id}/delete`
*   **Method:** `POST`
*   **Authorization:** Requires active cookie token belonging to an administrator.
*   **Response (200 OK):**
    ```json
    {
      "success": true
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: If trying to delete your own administrator account.
    *   `403 Forbidden`: Unauthorized admin access.
    *   `404 Not Found`: Target user ID does not exist.
