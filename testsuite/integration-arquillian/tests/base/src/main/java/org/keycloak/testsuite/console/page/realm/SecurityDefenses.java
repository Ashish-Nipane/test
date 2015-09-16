/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.console.page.realm;

import org.jboss.arquillian.graphene.findby.FindByJQuery;
import org.jboss.arquillian.graphene.page.Page;
import org.keycloak.testsuite.console.page.fragment.OnOffSwitch;
import org.keycloak.testsuite.page.Form;
import static org.keycloak.testsuite.page.Form.setInputValue;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.ui.Select;

/**
 * @author Filip Kiss
 * @author mhajas
 */
public class SecurityDefenses extends RealmSettings {

    @Override
    public String getUriFragment() {
        return super.getUriFragment() + "/defense"; // NOTE: page doesn't exist, only subpages
    }

    public class Headers extends SecurityDefenses {

        @Override
        public String getUriFragment() {
            return super.getUriFragment() + "/headers";
        }

        @Page
        private HeadersForm form;

        public HeadersForm form() {
            return form;
        }

        public class HeadersForm extends Form {

            @FindBy(id = "xFrameOptions")
            private WebElement xFrameOptions;

            public void setXFrameOptions(String value) {
                setInputValue(xFrameOptions, value);
            }

            @FindBy(id = "contentSecurityPolicy")
            private WebElement contentSecurityPolicy;

            public void setContentSecurityPolicy(String value) {
                setInputValue(contentSecurityPolicy, value);
            }
        }
    }

    public enum TimeSelectValues {

        SECONDS("Seconds"), MINUTES("Minutes"), HOURS("Hours"), DAYS("Days");

        private String name;

        private TimeSelectValues(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public class BruteForceDetection extends SecurityDefenses {

        @Override
        public String getUriFragment() {
            return super.getUriFragment() + "/brute-force";
        }

        @Page
        private BruteForceDetectionForm form;

        public BruteForceDetectionForm form() {
            return form;
        }

        public class BruteForceDetectionForm extends Form {

            @FindByJQuery("div[class='onoffswitch']")
            private OnOffSwitch protectionEnabled;

            public void setProtectionEnabled(boolean protectionEnabled) {
                this.protectionEnabled.setOn(protectionEnabled);
            }

            @FindBy(id = "failureFactor")
            private WebElement maxLoginFailures;

            public void setMaxLoginFailures(String value) {
                setInputValue(maxLoginFailures, value);
            }

            @FindBy(id = "waitIncrement")
            private WebElement waitIncrementInput;

            @FindBy(name = "waitIncrementUnit")
            private Select waitIncrementSelect;

            public void setWaitIncrementInput(String value) {
                setInputValue(waitIncrementInput, value);
            }

            public void setWaitIncrementSelect(TimeSelectValues value) {
                waitIncrementSelect.selectByVisibleText(value.getName());
            }

            @FindBy(id = "quickLoginCheckMilliSeconds")
            private WebElement quickLoginCheckInput;

            public void setQuickLoginCheckInput(String value) {
                setInputValue(quickLoginCheckInput, value);
            }

            @FindBy(id = "minimumQuickLoginWait")
            private WebElement minQuickLoginWaitInput;

            @FindBy(name = "minimumQuickLoginWaitUnit")
            private Select minQuickLoginWaitSelect;

            public void setMinQuickLoginWaitInput(String value) {
                setInputValue(minQuickLoginWaitInput, value);
            }

            public void setMinQuickLoginWaitSelect(TimeSelectValues value) {
                minQuickLoginWaitSelect.selectByVisibleText(value.getName());
            }

            @FindBy(id = "maxFailureWait")
            private WebElement maxWaitInput;

            @FindBy(name = "maxFailureWaitUnit")
            private Select maxWaitSelect;

            public void setMaxWaitInput(String value) {
                setInputValue(maxWaitInput, value);
            }

            public void setMaxWaitSelect(TimeSelectValues value) {
                maxWaitSelect.selectByVisibleText(value.getName());
            }

            @FindBy(id = "maxDeltaTime")
            private WebElement failureResetTimeInput;

            @FindBy(name = "maxDeltaTimeUnit")
            private Select failureResetTimeSelect;

            public void setFailureResetTimeInput(String value) {
                setInputValue(failureResetTimeInput, value);
            }

            public void setFailureResetTimeSelect(TimeSelectValues value) {
                failureResetTimeSelect.selectByVisibleText(value.getName());
            }

        }

    }

    @FindByJQuery("a:contains('Brute Force Detection')")
    private WebElement bruteForceDetectionTab;

    public void goToBruteForceDetection() {
        bruteForceDetectionTab.click();
    }

    @FindByJQuery("a:contains('Headers')")
    private WebElement headersTab;

    public void goToHeaders() {
        headersTab.click();
    }
}
