/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.keycloak.services.scheduled;

import org.jboss.logging.Logger;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.logging.KeycloakLogger;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ScheduledTaskRunner implements Runnable {

    private static final KeycloakLogger logger = Logger.getMessageLogger(KeycloakLogger.class, ScheduledTaskRunner.class.getName());

    private final KeycloakSessionFactory sessionFactory;
    private final ScheduledTask task;

    public ScheduledTaskRunner(KeycloakSessionFactory sessionFactory, ScheduledTask task) {
        this.sessionFactory = sessionFactory;
        this.task = task;
    }

    @Override
    public void run() {
        KeycloakSession session = sessionFactory.create();
        try {
            session.getTransaction().begin();
            task.run(session);
            session.getTransaction().commit();

            logger.debug("Executed scheduled task " + task.getClass().getSimpleName());
        } catch (Throwable t) {
            logger.CONFIG.failedToRunScheduledTask(t, task.getClass().getSimpleName());

            session.getTransaction().rollback();
        } finally {
            try {
                session.close();
            } catch (Throwable t) {
                logger.CONFIG.failedToCloseProviderSession(t);
            }
        }
    }

}
