import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generatePath } from "../../util";
import type { AppRouteObject } from "../../routes";

export type UserFederationParams = { realm: string };

const UserFederationSection = lazy(() => import("../UserFederationSection"));

export const UserFederationRoute: AppRouteObject = {
  path: "/:realm/user-federation",
  element: <UserFederationSection />,
  breadcrumb: (t) => t("userFederation"),
  handle: {
    access: "view-realm",
  },
};

export const toUserFederation = (
  params: UserFederationParams,
): Partial<Path> => ({
  pathname: generatePath(UserFederationRoute.path, params),
});
