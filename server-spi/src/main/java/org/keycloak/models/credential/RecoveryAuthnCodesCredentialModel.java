package org.keycloak.models.credential;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.dto.RecoveryAuthnCodeRepresentation;
import org.keycloak.models.credential.dto.RecoveryAuthnCodesCredentialData;
import org.keycloak.models.credential.dto.RecoveryAuthnCodesSecretData;
import org.keycloak.models.utils.RecoveryAuthnCodesUtils;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RecoveryAuthnCodesCredentialModel extends CredentialModel {

    public static final String TYPE = "recovery-authn-codes";

    private final RecoveryAuthnCodesCredentialData credentialData;
    private final RecoveryAuthnCodesSecretData secretData;

    private RecoveryAuthnCodesCredentialModel(RecoveryAuthnCodesCredentialData credentialData,
                                              RecoveryAuthnCodesSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    public RecoveryAuthnCodeRepresentation getNextRecoveryAuthnCode() {
        return this.secretData.getCodes().get(0);
    }

    public boolean allCodesUsed() {
        return this.secretData.getCodes().isEmpty();
    }

    public void removeRecoveryAuthnCode() {
        try {
            this.secretData.removeNextBackupCode();
            this.credentialData.setRemainingCodes(this.secretData.getCodes().size());

            this.setSecretData(JsonSerialization.writeValueAsString(this.secretData));
            this.setCredentialData(JsonSerialization.writeValueAsString(this.credentialData));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static RecoveryAuthnCodesCredentialModel createFromValues(String[] originalGeneratedCodes,
                                                                     long generatedAt,
                                                                     String userLabel) {

        RecoveryAuthnCodesSecretData secretData;
        RecoveryAuthnCodesCredentialData credentialData;
        RecoveryAuthnCodesCredentialModel model;

        try {
            secretData = new RecoveryAuthnCodesSecretData(toRecoveryAuthnCodesRepresentationList(originalGeneratedCodes));

            credentialData = new RecoveryAuthnCodesCredentialData(RecoveryAuthnCodesUtils.NUM_HASH_ITERATIONS,
                                                                  RecoveryAuthnCodesUtils.NOM_ALGORITHM_TO_HASH,
                                                                  originalGeneratedCodes.length);

            model = new RecoveryAuthnCodesCredentialModel(credentialData, secretData);

            model.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            model.setSecretData(JsonSerialization.writeValueAsString(secretData));
            model.setCreatedDate(generatedAt);
            model.setType(TYPE);

            if (userLabel != null) {
                model.setUserLabel(userLabel);
            }

            return model;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<RecoveryAuthnCodeRepresentation> toRecoveryAuthnCodesRepresentationList(String[] rawGeneratedCodes) {
        List<RecoveryAuthnCodeRepresentation> recoveryAuthnCodeRepresentations = new ArrayList<>();
        RecoveryAuthnCodeRepresentation newAuthCodeRepresentation;

        for (int i = 0; i < rawGeneratedCodes.length; i++) {
            newAuthCodeRepresentation = new RecoveryAuthnCodeRepresentation(i + 1,
                                                                            (RecoveryAuthnCodesUtils.SHOULD_SAVE_RAW_RECOVERY_AUTHN_CODE ? rawGeneratedCodes[i] : null),
                                                                            RecoveryAuthnCodesUtils.hashRawCode(rawGeneratedCodes[i]));
            recoveryAuthnCodeRepresentations.add(newAuthCodeRepresentation);
        }

        return recoveryAuthnCodeRepresentations;
    }

    public static RecoveryAuthnCodesCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        RecoveryAuthnCodesCredentialData credentialData;
        RecoveryAuthnCodesSecretData secretData;
        RecoveryAuthnCodesCredentialModel newModel;

        try {
            credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
                                                         RecoveryAuthnCodesCredentialData.class);

            secretData = JsonSerialization.readValue(credentialModel.getSecretData(),
                                                     RecoveryAuthnCodesSecretData.class);

            newModel = new RecoveryAuthnCodesCredentialModel(credentialData, secretData);
            newModel.setUserLabel(credentialModel.getUserLabel());
            newModel.setCreatedDate(credentialModel.getCreatedDate());
            newModel.setType(TYPE);
            newModel.setId(credentialModel.getId());
            newModel.setSecretData(credentialModel.getSecretData());
            newModel.setCredentialData(credentialModel.getCredentialData());

            return newModel;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
