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
package org.keycloak.testsuite.broker.util;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.IDToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;

/**
 * @author pedroigor
 */
public class UserSessionStatusServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getRequestURI().toString().endsWith("logout")) {
            resp.setStatus(200);
            req.logout();
            return;
        }

        writeSessionStatus(req, resp);
    }

    private void writeSessionStatus(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        KeycloakSecurityContext context = (KeycloakSecurityContext)req.getAttribute(KeycloakSecurityContext.class.getName());
        IDToken idToken = context.getIdToken();
        JsonNode jsonNode = new ObjectMapper().valueToTree(new UserSessionStatus(idToken));
        PrintWriter writer = resp.getWriter();

        writer.println(jsonNode.toString());

        writer.flush();
    }

    public static class UserSessionStatus implements Serializable {

        private IDToken idToken;

        public UserSessionStatus() {

        }

        public UserSessionStatus(IDToken idToken) {
            this.idToken = idToken;
        }

        public IDToken getIdToken() {
            return this.idToken;
        }

        public void setIdToken(IDToken idToken) {
            this.idToken = idToken;
        }
    }
}
