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
package org.keycloak.saml.processing.core.parsers.saml.assertion;

import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import java.net.URI;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

/**
 * Parse the <conditions> in the saml assertion
 *
 * @since Oct 14, 2010
 */
public class SAMLAudienceRestrictionParser extends AbstractStaxSamlAssertionParser<AudienceRestrictionType> {

    private static final SAMLAudienceRestrictionParser INSTANCE = new SAMLAudienceRestrictionParser();

    private SAMLAudienceRestrictionParser() {
        super(SAMLAssertionQNames.AUDIENCE_RESTRICTION);
    }

    public static SAMLAudienceRestrictionParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected AudienceRestrictionType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        return new AudienceRestrictionType();
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, AudienceRestrictionType target, SAMLAssertionQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case AUDIENCE:
                StaxParserUtil.advance(xmlEventReader);
                String audienceValue = StaxParserUtil.getElementText(xmlEventReader);
                try {
                    LOGGER.warn("SAMLAudienceRestrictionParser 1");
                    URI audienceURI = URI.create(audienceValue);
                    target.addAudience("https://localhost/keycloak/auth/realms/opendata/broker/nias/endpoint");
                    LOGGER.warn("SAMLAudienceRestrictionParser success");
                } catch (IllegalArgumentException e) {
                    // Ignore parse error
                    LOGGER.warn("SAMLAudienceRestrictionParser IllegalArgumentException 1");
                    LOGGER.warn("SAMLAudienceRestrictionParser IllegalArgumentException success");
                }
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}