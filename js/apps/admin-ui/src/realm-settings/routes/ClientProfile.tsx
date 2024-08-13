import { lazy } from "react";
import { generatePath, type Path } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type ClientProfileParams = {
  realm: string;
  profileName: string;
};

const ClientProfileForm = lazy(() => import("../ClientProfileForm"));

export const ClientProfileRoute: AppRouteObject = {
  path: "/:realm/realm-settings/client-policies/:profileName/edit-profile",
  element: <ClientProfileForm />,
  breadcrumb: (t) => t("clientProfile"),
  handle: {
    access: ["view-realm", "view-users"],
  },
};

export const toClientProfile = (
  params: ClientProfileParams,
): Partial<Path> => ({
  pathname: generatePath(ClientProfileRoute.path, params),
});
