import { lazy } from "react";
import { generatePath, type Path } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type AddOrganizationParams = { realm: string };

const NewOrganization = lazy(() => import("../NewOrganization"));

export const AddOrganizationRoute: AppRouteObject = {
  path: "/:realm/organizations/new",
  element: <NewOrganization />,
  breadcrumb: (t) => t("createOrganization"),
  handle: {
    access: "manage-users",
  },
};

export const toAddOrganization = (
  params: AddOrganizationParams,
): Partial<Path> => ({
  pathname: generatePath(AddOrganizationRoute.path, params),
});
