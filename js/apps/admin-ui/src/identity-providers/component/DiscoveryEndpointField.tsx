import { FormGroup, Switch } from "@patternfly/react-core";
import debouncePromise from "awesome-debounce-promise";
import { ReactNode, useState } from "react";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { HelpItem, TextControl } from "ui-shared";
import { adminClient } from "../../admin-client";
import environment from "../../environment";

type DiscoveryEndpointFieldProps = {
  id: string;
  fileUpload: ReactNode;
  children: (readOnly: boolean) => ReactNode;
};

export const DiscoveryEndpointField = ({
  id,
  fileUpload,
  children,
}: DiscoveryEndpointFieldProps) => {
  const { t } = useTranslation();
  const {
    setValue,
    clearErrors,
    formState: { errors },
  } = useFormContext();
  const [discovery, setDiscovery] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [discoveryResult, setDiscoveryResult] =
    useState<Record<string, string>>();

  const setupForm = (result: Record<string, string>) => {
    Object.keys(result).map((k) => setValue(`config.${k}`, result[k]));
  };

  const discover = async (fromUrl: string) => {
    setDiscovering(true);
    try {
      const result = await adminClient.identityProviders.importFromUrl({
        providerId: id,
        fromUrl,
      });
      setupForm(result);
      setDiscoveryResult(result);
    } catch (error) {
      return (error as Error).message;
    } finally {
      setDiscovering(false);
    }
  };

  return (
    <>
      <FormGroup
        label={t(
          id === "oidc" ? "useDiscoveryEndpoint" : "useEntityDescriptor",
        )}
        fieldId="kc-discovery-endpoint"
        labelIcon={
          <HelpItem
            helpText={t(
              id === "oidc"
                ? "useDiscoveryEndpointHelp"
                : "useEntityDescriptorHelp",
            )}
            fieldLabelId="discoveryEndpoint"
          />
        }
      >
        <Switch
          id="kc-discovery-endpoint-switch"
          label={t("on")}
          labelOff={t("off")}
          isChecked={discovery}
          onChange={(checked) => {
            clearErrors("discoveryError");
            setDiscovery(checked);
          }}
          aria-label={t(
            id === "oidc" ? "useDiscoveryEndpoint" : "useEntityDescriptor",
          )}
        />
      </FormGroup>
      {discovery && (
        <TextControl
          name="discoveryEndpoint"
          label={t(
            id === "oidc" ? "discoveryEndpoint" : "samlEntityDescriptor",
          )}
          labelIcon={t(
            id === "oidc"
              ? "discoveryEndpointHelp"
              : "samlEntityDescriptorHelp",
          )}
          type="url"
          placeholder={
            id === "oidc"
              ? "https://hostname/auth/realms/master/.well-known/openid-configuration"
              : ""
          }
          validated={
            errors.discoveryError || errors.discoveryEndpoint
              ? "error"
              : !discoveryResult
                ? "default"
                : "success"
          }
          customIconUrl={
            discovering
              ? environment.resourceUrl + "/discovery-load-indicator.svg"
              : ""
          }
          rules={{
            required: t("required"),
            validate: debouncePromise(
              async (value: string) => await discover(value),
              1000,
            ),
          }}
        />
      )}
      {!discovery && fileUpload}
      {discovery && !errors.discoveryError && children(true)}
      {!discovery && children(false)}
    </>
  );
};
