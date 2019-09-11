/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.forms;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:abraham.k@coda.global">Abraham K</a>
 * @version $Revision: 2 $
 *
 * reCAPTCHAv3 is a invisible captcha & it returns a score based on the interactions with your website and provides you more flexibility to take appropriate actions.
 * Ref: https://developers.google.com/recaptcha/docs/v3
 *
 */
public class RegistrationRecaptcha implements FormAction, FormActionFactory, ConfiguredProvider {
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String RECAPTCHA_REFERENCE_CATEGORY = "recaptcha";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String SITE_SCORE = "site.score";
    public static final String SITE_VERSION = "site.version";
    public static final String SITE_ACTION = "recaptcha.action";
    private static final Logger logger = Logger.getLogger(RegistrationRecaptcha.class);

    public static final String PROVIDER_ID = "registration-recaptcha-action";

    @Override
    public String getDisplayType() {
        return "Recaptcha";
    }

    @Override
    public String getReferenceCategory() {
        return RECAPTCHA_REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null
                ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }
        // For Backward Compatibility / Previous Captcha users
        if(captchaConfig.getConfig().get(SITE_VERSION) == null || captchaConfig.getConfig().get(SITE_VERSION) == ""){
            Map<String, String> versionDefaultMap = new HashMap<String, String>();
            versionDefaultMap.put(SITE_VERSION, "v2");
            captchaConfig.setConfig(versionDefaultMap);
        }
        String siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String siteActionName = captchaConfig.getConfig().get(SITE_ACTION);
        String siteVersion = captchaConfig.getConfig().get(SITE_VERSION);
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.setAttribute("recaptchaSiteVersion", siteVersion);
        form.setAttribute("recaptchaActionName", siteActionName);
        if(siteVersion.equals("v3")){
            form.addScript("https://www.google.com/recaptcha/api.js?hl=" + userLanguageTag + "&render=" + siteKey + "&onload=onRecaptchaLoaded");
        } else {
            form.addScript("https://www.google.com/recaptcha/api.js?hl=" + userLanguageTag );
        }
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String secret = captchaConfig.getConfig().get(SITE_SECRET);

            success = validateRecaptcha(context, success, captcha, secret);
        }
        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(G_RECAPTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;


        }
    }

    protected boolean validateRecaptcha(ValidationContext context, boolean success, String captcha, String secret) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                Object val = json.get("success");
                AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
                String siteVersion = captchaConfig.getConfig().get(SITE_VERSION);
                System.out.println(siteVersion);
                if(siteVersion.equals("v2")){
                    success = Boolean.TRUE.equals(val);
                } else {
                    Double userScore = Double.parseDouble(json.get("score").toString());
                    Double configScore = Double.parseDouble(captchaConfig.getConfig().get(SITE_SCORE));
                    if(userScore > configScore){
                        success = true;
                    } else {
                        success = false;
                    }
                }
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds Google Recaptcha button.  Recaptchas verify that the entity that is registering is a human.  This can only be used on the internet and must be configured after you add it.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(SITE_VERSION);
        property.setLabel("reCAPTCHA Version");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        List<String> list = new ArrayList<>();
        list.add("v2");
        list.add("v3");
        property.setOptions(list);
        property.setDefaultValue("v2");
        property.setHelpText("Google reCAPTCHA v2 or reCAPTCHA v3");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_KEY);
        property.setLabel("reCAPTCHA Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google reCAPTCHA Site Key");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_SECRET);
        property.setLabel("reCAPTCHA Secret Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google reCAPTCHA Site Secret Key");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_SCORE);
        property.setLabel("reCAPTCHA Score");
        property.setDefaultValue(0.5);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google reCAPTCHA Score (0.1 - 1.0) - Applicable only for reCAPTCHA v3");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_ACTION);
        property.setLabel("reCAPTCHAv3 Action");
        property.setDefaultValue("kc_registration_page");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google reCAPTCHAv3 Action Name - Applicable only for reCAPTCHA v3");
        CONFIG_PROPERTIES.add(property);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
