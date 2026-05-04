import { HearthError } from "./client.js";
import type {
  CreateRealmParams,
  CreateUserParams,
  PageResponse,
  Realm,
  UpdateRealmParams,
  UpdateUserParams,
  User,
} from "./types.js";

/**
 * Admin API client for Hearth.
 *
 * Requires a valid admin access token. All operations go through
 * the /admin/* endpoints which enforce RBAC admin role checks.
 */
export class AdminClient {
  constructor(
    private readonly baseUrl: string,
    private readonly realmId: string,
    private readonly accessToken: string,
  ) {}

  // === Users ===

  /** POST /admin/users — create a user. */
  async createUser(params: CreateUserParams): Promise<User> {
    return this.post("/admin/users", {
      email: params.email,
      display_name: params.displayName,
    });
  }

  /** GET /admin/users — list users with pagination. */
  async listUsers(options?: {
    limit?: number;
    cursor?: string;
  }): Promise<PageResponse<User>> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    return this.get(`/admin/users?${q}`);
  }

  /** GET /admin/users/:id — get a user by ID. */
  async getUser(userId: string): Promise<User> {
    return this.get(`/admin/users/${userId}`);
  }

  /** PUT /admin/users/:id — update a user. */
  async updateUser(userId: string, params: UpdateUserParams): Promise<User> {
    return this.request("PUT", `/admin/users/${userId}`, {
      email: params.email,
      display_name: params.displayName,
      status: params.status,
    });
  }

  /** DELETE /admin/users/:id — delete a user. */
  async deleteUser(userId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/users/${userId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  // === Realms ===

  /** POST /admin/realms — create a realm. */
  async createRealm(params: CreateRealmParams): Promise<Realm> {
    return this.post("/admin/realms", {
      name: params.name,
      config: params.config,
    });
  }

  /** GET /admin/realms — list realms with pagination. */
  async listRealms(options?: {
    limit?: number;
    cursor?: string;
  }): Promise<PageResponse<Realm>> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    return this.get(`/admin/realms?${q}`);
  }

  /** GET /admin/realms/:id — get a realm by ID. */
  async getRealm(realmId: string): Promise<Realm> {
    return this.get(`/admin/realms/${realmId}`);
  }

  /** PUT /admin/realms/:id — update a realm. */
  async updateRealm(
    realmId: string,
    params: UpdateRealmParams,
  ): Promise<Realm> {
    return this.request("PUT", `/admin/realms/${realmId}`, {
      name: params.name,
      status: params.status,
      config: params.config,
    });
  }

  /** DELETE /admin/realms/:id — delete a realm. */
  async deleteRealm(realmId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/realms/${realmId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  private headers(): Record<string, string> {
    return {
      "X-Realm-ID": this.realmId,
      Authorization: `Bearer ${this.accessToken}`,
      "Content-Type": "application/json",
    };
  }

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
  ): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }
}
