import { lazy } from "react";
import { generatePath, type Path } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type ScopeDetailsParams = {
  realm: string;
  id: string;
  scopeId?: string;
};

const ScopeDetails = lazy(() => import("../authorization/ScopeDetails"));

export const ScopeDetailsRoute: AppRouteObject = {
  path: "/:realm/clients/:id/authorization/scope",
  element: <ScopeDetails />,
  breadcrumb: (t) => t("authorizationScopeDetails"),
  handle: {
    access: (accessChecker) =>
      accessChecker.hasAny("manage-clients", "view-authorization"),
  },
};

export const ScopeDetailsWithScopeIdRoute: AppRouteObject = {
  ...ScopeDetailsRoute,
  path: "/:realm/clients/:id/authorization/scope/:scopeId",
};

export const toScopeDetails = (params: ScopeDetailsParams): Partial<Path> => {
  const path = params.scopeId
    ? ScopeDetailsWithScopeIdRoute.path
    : ScopeDetailsRoute.path;

  return {
    pathname: generatePath(path, params),
  };
};
