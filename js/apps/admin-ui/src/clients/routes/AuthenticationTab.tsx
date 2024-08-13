import { lazy } from "react";
import { generatePath, type Path } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type AuthorizationTab =
  | "settings"
  | "resources"
  | "scopes"
  | "policies"
  | "permissions"
  | "evaluate"
  | "export";

export type AuthorizationParams = {
  realm: string;
  clientId: string;
  tab: AuthorizationTab;
};

const ClientDetails = lazy(() => import("../ClientDetails"));

export const AuthorizationRoute: AppRouteObject = {
  path: "/:realm/clients/:clientId/authorization/:tab",
  element: <ClientDetails />,
  breadcrumb: (t) => t("clientSettings"),
  handle: {
    access: (accessChecker) =>
      accessChecker.hasAny("view-authorization", "manage-authorization"),
  },
};

export const toAuthorizationTab = (
  params: AuthorizationParams,
): Partial<Path> => ({
  pathname: generatePath(AuthorizationRoute.path, params),
});
