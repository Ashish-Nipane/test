package org.keycloak.testsuite;

import org.hamcrest.CoreMatchers;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.keycloak.audit.AuditListener;
import org.keycloak.audit.AuditListenerFactory;
import org.keycloak.audit.Details;
import org.keycloak.audit.Event;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderSession;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.testsuite.rule.KeycloakRule;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AssertEvents implements TestRule, AuditListenerFactory {

    public static String DEFAULT_CLIENT_ID = "test-app";
    public static String DEFAULT_REDIRECT_URI = "http://localhost:8081/app/auth";
    public static String DEFAULT_IP_ADDRESS = "127.0.0.1";
    public static String DEFAULT_REALM = "test";
    public static String DEFAULT_USERNAME = "test-user@localhost";

    private KeycloakRule keycloak;

    private static BlockingQueue<Event> events = new LinkedBlockingQueue<Event>();

    public AssertEvents() {
    }

    public AssertEvents(KeycloakRule keycloak) {
        this.keycloak = keycloak;
    }

    @Override
    public String getId() {
        return "assert-events";
    }

    @Override
    public boolean lazyLoad() {
        return false;
    }

    @Override
    public Statement apply(final Statement base, org.junit.runner.Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                events.clear();

                keycloak.configure(new KeycloakRule.KeycloakSetup() {
                    @Override
                    public void config(RealmManager manager, RealmModel adminstrationRealm, RealmModel appRealm) {
                        Set<String> listeners = new HashSet<String>();
                        listeners.add("jboss-logging");
                        listeners.add("assert-events");
                        appRealm.setAuditListeners(listeners);
                    }
                });

                try {
                    base.evaluate();

                    Event event = events.peek();
                    if (event != null) {
                        Assert.fail("Unexpected event after test: " + event.getEvent());
                    }
                } finally {
                    keycloak.configure(new KeycloakRule.KeycloakSetup() {
                        @Override
                        public void config(RealmManager manager, RealmModel adminstrationRealm, RealmModel appRealm) {
                            appRealm.setAuditListeners(null);
                        }
                    });
                }
            }
        };
    }

    public void assertEmpty() {
         Assert.assertTrue(events.isEmpty());
    }

    public Event poll() {
        try {
            return events.poll(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            return null;
        }
    }

    public void clear() {
        events.clear();
    }

    public ExpectedEvent expectRequiredAction(String event) {
        return expectLogin().event(event);
    }

    public ExpectedEvent expectLogin() {
        return expect("login")
                .detail(Details.CODE_ID, isCodeId())
                .detail(Details.USERNAME, DEFAULT_USERNAME)
                .detail(Details.RESPONSE_TYPE, "code")
                .detail(Details.AUTH_METHOD, "form")
                .detail(Details.REDIRECT_URI, DEFAULT_REDIRECT_URI);
    }

    public ExpectedEvent expectCodeToToken(String codeId) {
        return expect("code_to_token")
                .detail(Details.CODE_ID, codeId)
                .detail(Details.TOKEN_ID, isUUID())
                .detail(Details.REFRESH_TOKEN_ID, isUUID());
    }

    public ExpectedEvent expectRefresh(String refreshTokenId) {
        return expect("refresh_token")
                .detail(Details.TOKEN_ID, isUUID())
                .detail(Details.REFRESH_TOKEN_ID, refreshTokenId)
                .detail(Details.UPDATED_REFRESH_TOKEN_ID, isUUID());
    }

    public ExpectedEvent expectLogout() {
        return expect("logout").client((String) null)
                .detail(Details.REDIRECT_URI, DEFAULT_REDIRECT_URI);
    }

    public ExpectedEvent expectRegister(String username, String email) {
        UserRepresentation user = keycloak.getUser("test", username);
        return expect("register")
                .user(user != null ? user.getId() : null)
                .detail(Details.USERNAME, username)
                .detail(Details.EMAIL, email)
                .detail(Details.RESPONSE_TYPE, "code")
                .detail(Details.REGISTER_METHOD, "form")
                .detail(Details.REDIRECT_URI, DEFAULT_REDIRECT_URI);
    }

    public ExpectedEvent expectAccount(String event) {
        return expect(event).client("account");
    }

    public ExpectedEvent expect(String event) {
        return new ExpectedEvent().realm(DEFAULT_REALM).client(DEFAULT_CLIENT_ID).user(keycloak.getUser(DEFAULT_REALM, DEFAULT_USERNAME).getId()).ipAddress(DEFAULT_IP_ADDRESS).event(event);
    }

    @Override
    public AuditListener create(ProviderSession providerSession) {
        return new AuditListener() {
            @Override
            public void onEvent(Event event) {
                events.add(event);
            }

            @Override
            public void close() {
            }
        };
    }

    @Override
    public void init() {
    }

    @Override
    public void close() {
    }

    public static class ExpectedEvent {
        private Event expected = new Event();
        private Matcher<String> userId;
        private HashMap<String, Matcher<String>> details;

        public ExpectedEvent realm(RealmModel realm) {
            expected.setRealmId(realm.getId());
            return this;
        }

        public ExpectedEvent realm(String realmId) {
            expected.setRealmId(realmId);
            return this;
        }

        public ExpectedEvent client(ClientModel client) {
            expected.setClientId(client.getClientId());
            return this;
        }

        public ExpectedEvent client(String clientId) {
            expected.setClientId(clientId);
            return this;
        }

        public ExpectedEvent user(UserModel user) {
            return user(CoreMatchers.equalTo(user.getId()));
        }

        public ExpectedEvent user(String userId) {
            return user(CoreMatchers.equalTo(userId));
        }

        public ExpectedEvent user(Matcher<String> userId) {
            this.userId = userId;
            return this;
        }

        public ExpectedEvent ipAddress(String ipAddress) {
            expected.setIpAddress(ipAddress);
            return this;
        }

        public ExpectedEvent event(String e) {
            expected.setEvent(e);
            return this;
        }

        public ExpectedEvent detail(String key, String value) {
            return detail(key, CoreMatchers.equalTo(value));
        }

        public ExpectedEvent detail(String key, Matcher<String> matcher) {
            if (details == null) {
                details = new HashMap<String, Matcher<String>>();
            }
            details.put(key, matcher);
            return this;
        }

        public ExpectedEvent removeDetail(String key) {
            if (details != null) {
                details.remove(key);
            }
            return this;
        }

        public ExpectedEvent error(String error) {
            expected.setError(error);
            return this;
        }

        public Event assertEvent() {
            try {
                return assertEvent(events.poll(10, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                throw new AssertionError("No event received within timeout");
            }
        }

        public Event assertEvent(Event actual) {
            Assert.assertEquals(expected.getEvent(), actual.getEvent());
            Assert.assertEquals(expected.getRealmId(), actual.getRealmId());
            Assert.assertEquals(expected.getClientId(), actual.getClientId());
            Assert.assertEquals(expected.getError(), actual.getError());
            Assert.assertEquals(expected.getIpAddress(), actual.getIpAddress());
            Assert.assertThat(actual.getUserId(), userId);

            if (details == null) {
                Assert.assertNull(actual.getDetails());
            } else {
                Assert.assertNotNull(actual.getDetails());
                for (Map.Entry<String, Matcher<String>> d : details.entrySet()) {
                    String actualValue = actual.getDetails().get(d.getKey());
                    if (!actual.getDetails().containsKey(d.getKey())) {
                        Assert.fail(d.getKey() + " missing");
                    }

                    if (!d.getValue().matches(actualValue)) {
                        Assert.fail(d.getKey() + " doesn't match");
                    }
                }

                for (String k : actual.getDetails().keySet()) {
                    if (!details.containsKey(k)) {
                        Assert.fail(k + " was not expected");
                    }
                }
            }

            return actual;
        }
    }

    public static Matcher<String> isCodeId() {
        return new TypeSafeMatcher<String>() {
            @Override
            protected boolean matchesSafely(String item) {
                return (UUID.randomUUID().toString() + System.currentTimeMillis()).length() == item.length();
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("Not an Code ID");
            }
        };
    }

    public static Matcher<String> isUUID() {
        return new TypeSafeMatcher<String>() {
            @Override
            protected boolean matchesSafely(String item) {
                return KeycloakModelUtils.generateId().length() == item.length();
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("Not an UUID");
            }
        };
    }

}
