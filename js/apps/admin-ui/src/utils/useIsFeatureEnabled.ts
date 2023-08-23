import { useServerInfo } from "../context/server-info/ServerInfoProvider";

export enum Feature {
  AdminFineGrainedAuthz = "ADMIN_FINE_GRAINED_AUTHZ",
  ClientPolicies = "CLIENT_POLICIES",
  DeclarativeUserProfile = "DECLARATIVE_USER_PROFILE",
  Kerberos = "KERBEROS",
  DynamicScopes = "DYNAMIC_SCOPES",
  DPoP = "DPOP",
}

export default function useIsFeatureEnabled() {
  const { features } = useServerInfo();

  return function isFeatureEnabled(feature: Feature) {
    return features
      ?.filter((f) => f.enabled)
      .map((f) => f.name)
      .includes(feature);
  };
}
