// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import * as React from "react";
import { createHearth } from "../src/hearth.js";
import {
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "../src/react.js";

function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const sig = Buffer.from("not-a-real-signature").toString("base64url");
  return `${header}.${body}.${sig}`;
}

function Probe(): React.ReactElement {
  const canEdit = useHasPermission("docs.edit");
  const isAdmin = useHasRole("admin");
  const inEng = useInGroup("engineering");
  const inOrg42 = useInOrg("org_42");
  return (
    <div>
      <span data-testid="perm">{String(canEdit)}</span>
      <span data-testid="role">{String(isAdmin)}</span>
      <span data-testid="group">{String(inEng)}</span>
      <span data-testid="org">{String(inOrg42)}</span>
    </div>
  );
}

describe("react hooks", () => {
  afterEach(() => {
    cleanup();
  });

  it("reads RBAC claims from the provider client", () => {
    const token = forgeJwt({
      permissions: ["docs.edit"],
      roles: ["admin"],
      groups: ["engineering"],
      oid: "org_42",
    });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    render(
      <HearthProvider client={hearth}>
        <Probe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("perm").textContent).toBe("true");
    expect(screen.getByTestId("role").textContent).toBe("true");
    expect(screen.getByTestId("group").textContent).toBe("true");
    expect(screen.getByTestId("org").textContent).toBe("true");
  });

  it("returns false when the JWT lacks the requested claims", () => {
    const token = forgeJwt({ sub: "user_1" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    render(
      <HearthProvider client={hearth}>
        <Probe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("perm").textContent).toBe("false");
    expect(screen.getByTestId("role").textContent).toBe("false");
    expect(screen.getByTestId("group").textContent).toBe("false");
    expect(screen.getByTestId("org").textContent).toBe("false");
  });

  it("returns false when no HearthProvider is mounted", () => {
    render(<Probe />);
    expect(screen.getByTestId("perm").textContent).toBe("false");
    expect(screen.getByTestId("role").textContent).toBe("false");
    expect(screen.getByTestId("group").textContent).toBe("false");
    expect(screen.getByTestId("org").textContent).toBe("false");
  });
});
