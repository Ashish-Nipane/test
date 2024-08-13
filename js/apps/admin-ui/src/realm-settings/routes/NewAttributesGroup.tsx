import { lazy } from "react";
import { generatePath, type Path } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type NewAttributesGroupParams = {
  realm: string;
};

const AttributesGroupDetails = lazy(
  () => import("../user-profile/AttributesGroupDetails"),
);

export const NewAttributesGroupRoute: AppRouteObject = {
  path: "/:realm/realm-settings/user-profile/attributesGroup/new",
  element: <AttributesGroupDetails />,
  breadcrumb: (t) => t("createGroupText"),
  handle: {
    access: "view-realm",
  },
};

export const toNewAttributesGroup = (
  params: NewAttributesGroupParams,
): Partial<Path> => ({
  pathname: generatePath(NewAttributesGroupRoute.path, params),
});
