package org.keycloak.models.mongo.keycloak.credentials;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.keycloak.models.mongo.api.NoSQL;
import org.keycloak.models.mongo.api.query.NoSQLQuery;
import org.keycloak.models.mongo.keycloak.data.UserData;
import org.keycloak.models.mongo.keycloak.data.credentials.PasswordData;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.encoder.PasswordEncoder;
import org.picketlink.idm.credential.encoder.SHAPasswordEncoder;

/**
 * Defacto forked from {@link org.picketlink.idm.credential.handler.PasswordCredentialHandler}
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PasswordCredentialHandler {

    private static final String DEFAULT_SALT_ALGORITHM = "SHA1PRNG";

    /**
     * <p>
     * Stores a <b>stateless</b> instance of {@link org.picketlink.idm.credential.encoder.PasswordEncoder} that should be used to encode passwords.
     * </p>
     */
    public static final String PASSWORD_ENCODER = "PASSWORD_ENCODER";

    private PasswordEncoder passwordEncoder = new SHAPasswordEncoder(512);;

    public PasswordCredentialHandler(Map<String, Object> options) {
        setup(options);
    }

    private void setup(Map<String, Object> options) {
        if (options != null) {
            Object providedEncoder = options.get(PASSWORD_ENCODER);

            if (providedEncoder != null) {
                if (PasswordEncoder.class.isInstance(providedEncoder)) {
                    this.passwordEncoder = (PasswordEncoder) providedEncoder;
                } else {
                    throw new IllegalArgumentException("The password encoder [" + providedEncoder
                            + "] must be an instance of " + PasswordEncoder.class.getName());
                }
            }
        }
    }

    public Credentials.Status validate(NoSQL noSQL, UserData user, String passwordToValidate) {
        Credentials.Status status = Credentials.Status.INVALID;

        user = noSQL.loadObject(UserData.class, user.getId());

        // If the user for the provided username cannot be found we fail validation
        if (user != null) {
            if (user.isEnabled()) {
                NoSQLQuery query = noSQL.createQueryBuilder()
                        .andCondition("userId", user.getId())
                        .build();
                PasswordData passwordData = noSQL.loadSingleObject(PasswordData.class, query);

                // If the stored hash is null we automatically fail validation
                if (passwordData != null) {
                    // TODO: Status.INVALID should have bigger priority than Status.EXPIRED?
                    if (!isCredentialExpired(passwordData.getExpiryDate())) {

                        boolean matches = this.passwordEncoder.verify(saltPassword(passwordToValidate, passwordData.getSalt()), passwordData.getEncodedHash());

                        if (matches) {
                            status = Credentials.Status.VALID;
                        }
                    } else {
                        status = Credentials.Status.EXPIRED;
                    }
                }
            } else {
                status = Credentials.Status.ACCOUNT_DISABLED;
            }
        }

        return status;
    }

    public void update(NoSQL noSQL, UserData user, String password,
                       Date effectiveDate, Date expiryDate) {

        // Delete existing password of user
        NoSQLQuery query = noSQL.createQueryBuilder()
                .andCondition("userId", user.getId())
                .build();
        noSQL.removeObjects(PasswordData.class, query);

        PasswordData passwordData = new PasswordData();

        String passwordSalt = generateSalt();

        passwordData.setSalt(passwordSalt);
        passwordData.setEncodedHash(this.passwordEncoder.encode(saltPassword(password, passwordSalt)));

        if (effectiveDate != null) {
            passwordData.setEffectiveDate(effectiveDate);
        }

        passwordData.setExpiryDate(expiryDate);

        passwordData.setUserId(user.getId());

        noSQL.saveObject(passwordData);
    }

    /**
     * <p>
     * Salt the give <code>rawPassword</code> with the specified <code>salt</code> value.
     * </p>
     *
     * @param rawPassword
     * @param salt
     * @return
     */
    private String saltPassword(String rawPassword, String salt) {
        return salt + rawPassword;
    }

    /**
     * <p>
     * Generates a random string to be used as a salt for passwords.
     * </p>
     *
     * @return
     */
    private String generateSalt() {
        // TODO: always returns same salt (See https://issues.jboss.org/browse/PLINK-258)
        /*SecureRandom pseudoRandom = null;

        try {
            pseudoRandom = SecureRandom.getInstance(DEFAULT_SALT_ALGORITHM);
            pseudoRandom.setSeed(1024);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error getting SecureRandom instance: " + DEFAULT_SALT_ALGORITHM, e);
        }

        return String.valueOf(pseudoRandom.nextLong());*/
        return UUID.randomUUID().toString();
    }

    public static boolean isCredentialExpired(Date expiryDate) {
        return expiryDate != null && new Date().compareTo(expiryDate) > 0;
    }


}
