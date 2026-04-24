import * as React from "react";
import type { HearthFacade } from "./hearth.js";

/**
 * React context carrying a {@link HearthFacade} down the tree.
 *
 * The default value is `null`; the hooks treat a `null` context as
 * unauthenticated and return `false`.
 */
export const HearthContext = React.createContext<HearthFacade | null>(null);

/** Props for {@link HearthProvider}. */
export interface HearthProviderProps {
  client: HearthFacade;
  children: React.ReactNode;
}

/**
 * Provides a {@link HearthFacade} to descendants via {@link HearthContext}.
 *
 * Wrap your React tree once with this after calling `createHearth(...)`.
 */
export function HearthProvider(props: HearthProviderProps): React.ReactElement {
  return React.createElement(
    HearthContext.Provider,
    { value: props.client },
    props.children,
  );
}

/**
 * Returns `true` iff the nearest {@link HearthProvider} client reports
 * the permission as present in the JWT claim set. Returns `false`
 * when no provider is mounted.
 */
export function useHasPermission(permission: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasPermission(permission);
}

/** Returns `true` iff the JWT `roles` claim contains `role`. */
export function useHasRole(role: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasRole(role);
}

/** Returns `true` iff the JWT `groups` claim contains `group`. */
export function useInGroup(group: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inGroup(group);
}

/** Returns `true` iff the JWT `oid` claim equals `org`. */
export function useInOrg(org: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inOrg(org);
}
