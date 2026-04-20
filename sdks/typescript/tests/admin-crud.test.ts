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

  it("performs full CRUD on users and realms via the admin API", async () => {
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
    expect(user.status).toBe("USER_STATUS_ACTIVE");

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

    // === Realm CRUD ===

    // Create
    const realm = await admin.createRealm({
      name: "test-realm-crud",
    });
    expect(realm.id).toBeTruthy();
    expect(realm.name).toBe("test-realm-crud");
    expect(realm.status).toBe("REALM_STATUS_ACTIVE");

    // Read
    const fetchedRealm = await admin.getRealm(realm.id);
    expect(fetchedRealm.id).toBe(realm.id);
    expect(fetchedRealm.name).toBe("test-realm-crud");

    // Update
    const updatedRealm = await admin.updateRealm(realm.id, {
      name: "updated-realm-name",
    });
    expect(updatedRealm.name).toBe("updated-realm-name");

    // List
    const realmPage = await admin.listRealms({ limit: 10 });
    expect(realmPage.items.length).toBeGreaterThanOrEqual(1);

    // Delete
    await admin.deleteRealm(realm.id);

    // Verify deleted — should 404
    try {
      await admin.getRealm(realm.id);
      expect.fail("should have thrown");
    } catch (e: unknown) {
      expect((e as { status: number }).status).toBe(404);
    }
  });
});
