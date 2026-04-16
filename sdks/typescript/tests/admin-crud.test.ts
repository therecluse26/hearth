import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ensureBinary, startServer, stopServer, type TestServer } from "./helpers.js";

describe("TypeScript SDK: Admin CRUD", () => {
  let server: TestServer;

  beforeAll(async () => {
    ensureBinary();
    server = await startServer();
  });

  afterAll(() => {
    if (server) stopServer(server);
  });

  it("performs full CRUD on users and tenants via the admin API", async () => {
    const admin = server.client.admin(server.bootstrap.access_token);

    // === User CRUD ===

    // Create
    const user = await admin.createUser({
      email: "crud-test@test.local",
      displayName: "CRUD Test User",
    });
    expect(user.id).toBeTruthy();
    expect(user.email).toBe("crud-test@test.local");
    expect(user.display_name).toBe("CRUD Test User");
    expect(user.status).toBe("Active");

    // Read
    const fetched = await admin.getUser(user.id);
    expect(fetched.id).toBe(user.id);
    expect(fetched.email).toBe("crud-test@test.local");

    // Update
    const updated = await admin.updateUser(user.id, {
      displayName: "Updated Name",
    });
    expect(updated.display_name).toBe("Updated Name");
    expect(updated.email).toBe("crud-test@test.local");

    // List
    const page = await admin.listUsers({ limit: 10 });
    expect(page.items.length).toBeGreaterThanOrEqual(1);
    const found = page.items.find((u) => u.id === user.id);
    expect(found).toBeTruthy();
    expect(found!.display_name).toBe("Updated Name");

    // Delete
    await admin.deleteUser(user.id);

    // Verify deleted — should 404
    try {
      await admin.getUser(user.id);
      expect.fail("should have thrown");
    } catch (e: unknown) {
      expect((e as { status: number }).status).toBe(404);
    }

    // === Tenant CRUD ===

    // Create
    const tenant = await admin.createTenant({
      name: "test-tenant-crud",
    });
    expect(tenant.id).toBeTruthy();
    expect(tenant.name).toBe("test-tenant-crud");
    expect(tenant.status).toBe("Active");

    // Read
    const fetchedTenant = await admin.getTenant(tenant.id);
    expect(fetchedTenant.id).toBe(tenant.id);
    expect(fetchedTenant.name).toBe("test-tenant-crud");

    // Update
    const updatedTenant = await admin.updateTenant(tenant.id, {
      name: "updated-tenant-name",
    });
    expect(updatedTenant.name).toBe("updated-tenant-name");

    // List
    const tenantPage = await admin.listTenants({ limit: 10 });
    expect(tenantPage.items.length).toBeGreaterThanOrEqual(1);

    // Delete
    await admin.deleteTenant(tenant.id);

    // Verify deleted — should 404
    try {
      await admin.getTenant(tenant.id);
      expect.fail("should have thrown");
    } catch (e: unknown) {
      expect((e as { status: number }).status).toBe(404);
    }
  });
});
