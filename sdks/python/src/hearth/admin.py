"""AdminClient: user and realm CRUD operations (requires admin token)."""

from typing import Optional, List

import httpx

from .errors import HearthError
from .types import (
    User,
    CreateUserRequest,
    UpdateUserRequest,
    Realm,
    CreateRealmRequest,
    UpdateRealmRequest,
    PageResponse,
)


class AdminClient:
    """Client for Hearth admin operations (user and realm CRUD).

    Requires an admin access token obtained via ``/admin/bootstrap`` or
    from a user with the ``hearth.admin`` permission.

    Attributes:
        base_url: The Hearth server base URL.
        admin_token: A Bearer access token with admin privileges.
        realm_id: The realm to operate on.
    """

    def __init__(self, base_url: str, admin_token: str, realm_id: str, timeout: float = 30.0):
        self._base = base_url.rstrip("/")
        self._token = admin_token
        self._realm = realm_id
        self._http = httpx.Client(
            headers={
                "X-Realm-ID": realm_id,
                "Authorization": f"Bearer {admin_token}",
            },
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def create_user(self, req: CreateUserRequest) -> User:
        """Create a new user."""
        resp = self._http.post(
            f"{self._base}/admin/users", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def list_users(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[User]:
        """List users with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/users", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[User](**data)

    def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        resp = self._http.get(f"{self._base}/admin/users/{user_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def update_user(self, user_id: str, req: UpdateUserRequest) -> User:
        """Update an existing user."""
        resp = self._http.put(
            f"{self._base}/admin/users/{user_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def delete_user(self, user_id: str) -> None:
        """Delete a user."""
        resp = self._http.delete(f"{self._base}/admin/users/{user_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Realms
    # ------------------------------------------------------------------

    def create_realm(self, req: CreateRealmRequest) -> Realm:
        """Create a new realm."""
        resp = self._http.post(
            f"{self._base}/admin/realms", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def list_realms(self) -> List[Realm]:
        """List all realms."""
        resp = self._http.get(f"{self._base}/admin/realms")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return [Realm(**r) for r in data.get("items", data)]

    def get_realm(self, realm_id: str) -> Realm:
        """Get a realm by ID."""
        resp = self._http.get(f"{self._base}/admin/realms/{realm_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def update_realm(self, realm_id: str, req: UpdateRealmRequest) -> Realm:
        """Update an existing realm."""
        resp = self._http.put(
            f"{self._base}/admin/realms/{realm_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def delete_realm(self, realm_id: str) -> None:
        """Delete a realm."""
        resp = self._http.delete(f"{self._base}/admin/realms/{realm_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
