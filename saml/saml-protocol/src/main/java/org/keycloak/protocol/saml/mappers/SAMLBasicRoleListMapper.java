package org.keycloak.protocol.saml.mappers;

import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.saml.SamlProtocol;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SAMLBasicRoleListMapper extends AbstractSAMLProtocolMapper implements SAMLRoleListMapper {
    public static final String PROVIDER_ID = "saml-role-list-mapper";
    public static final String SINGLE_ROLE_ATTRIBUTE = "single";

    private static final List<ConfigProperty> configProperties = new ArrayList<ConfigProperty>();

    static {
        ConfigProperty property;
        property = new ConfigProperty();
        property.setName(AttributeStatementHelper.SAML_ATTRIBUTE_NAME);
        property.setLabel("Role attribute name");
        property.setDefaultValue("Role");
        property.setHelpText("Name of the SAML attribute you want to put your roles into.  i.e. 'Role', 'memberOf'.");
        configProperties.add(property);
        property = new ProtocolMapper.ConfigProperty();
        property.setName(AttributeStatementHelper.FRIENDLY_NAME);
        property.setLabel(AttributeStatementHelper.FRIENDLY_NAME_LABEL);
        property.setHelpText(AttributeStatementHelper.FRIENDLY_NAME_HELP_TEXT);
        configProperties.add(property);
        property = new ProtocolMapper.ConfigProperty();
        property.setName(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT);
        property.setLabel("SAML Attribute NameFormat");
        property.setHelpText("SAML Attribute NameFormat.  Can be basic, URI reference, or unspecified.");
        List<String> types = new ArrayList(3);
        types.add(AttributeStatementHelper.BASIC);
        types.add(AttributeStatementHelper.URI_REFERENCE);
        types.add(AttributeStatementHelper.UNSPECIFIED);
        property.setType(ProtocolMapper.ConfigProperty.LIST_TYPE);
        property.setDefaultValue(types);
        configProperties.add(property);
        property = new ConfigProperty();
        property.setName(SINGLE_ROLE_ATTRIBUTE);
        property.setLabel("Single Role Attribute");
        property.setType(ConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue("true");
        property.setHelpText("If true, all roles will be stored under one attribute with multiple attribute values.");
        configProperties.add(property);

    }


    @Override
    public String getDisplayCategory() {
        return "Role Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Role list";
    }

    @Override
    public String getHelpText() {
        return "Role names are stored in an attribute value.  There is either one attribute with multiple attribute values, or an attribute per role name depending on how you configure it.  You can also specify the attribute name i.e. 'Role' or 'memberOf' being examples.";
    }

    @Override
    public List<ConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void mapRoles(AttributeStatementType roleAttributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionModel clientSession) {
        String single = mappingModel.getConfig().get(SINGLE_ROLE_ATTRIBUTE);
        boolean singleAttribute = Boolean.parseBoolean(single);

        Map<ProtocolMapperModel, SAMLRoleNameMapper> roleNameMappers = new HashMap<>();
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        for (ProtocolMapperModel mapping : clientSession.getClient().getProtocolMappers()) {
            if (!mapping.getProtocol().equals(SamlProtocol.LOGIN_PROTOCOL)) continue;

            ProtocolMapper mapper = (ProtocolMapper)sessionFactory.getProviderFactory(ProtocolMapper.class, mapping.getProtocolMapper());
            if (mapper == null || !(mapper instanceof SAMLRoleNameMapper)) continue;
            roleNameMappers.put(mapping, (SAMLRoleNameMapper)mapper);
        }

        AttributeType singleAttributeType = null;
        for (String roleId : clientSession.getRoles()) {
            // todo need a role mapping
            RoleModel roleModel = clientSession.getRealm().getRoleById(roleId);
            AttributeType attributeType = null;
            if (singleAttribute) {
                if (singleAttributeType == null) {
                    singleAttributeType = AttributeStatementHelper.createAttributeType(mappingModel);
                    roleAttributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(singleAttributeType));
                }
                attributeType = singleAttributeType;
            } else {
                attributeType = AttributeStatementHelper.createAttributeType(mappingModel);
                roleAttributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attributeType));
            }
            String roleName = roleModel.getName();
            for (Map.Entry<ProtocolMapperModel, SAMLRoleNameMapper> entry : roleNameMappers.entrySet()) {
                String newName = entry.getValue().mapName(entry.getKey(), roleModel);
                if (newName != null) {
                    roleName = newName;
                    break;
                }
            }
            attributeType.addAttributeValue(roleName);
        }

    }

    public static ProtocolMapperModel create(String name, String samlAttributeName, String nameFormat, String friendlyName, boolean singleAttribute) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        mapper.setConsentRequired(false);
        Map<String, String> config = new HashMap<String, String>();
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, samlAttributeName);
        if (friendlyName != null) {
            config.put(AttributeStatementHelper.FRIENDLY_NAME, friendlyName);
        }
        if (nameFormat != null) {
            config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT, nameFormat);
        }
        config.put(SINGLE_ROLE_ATTRIBUTE, Boolean.toString(singleAttribute));
        mapper.setConfig(config);

        return mapper;
    }

}
