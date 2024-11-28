/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models.sessions.infinispan.changes;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Retry;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.tracing.TracingProvider;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Run one thread per session type and drain the queues once there is an entry. Will batch entries if possible.
 *
 * @author Alexander Schwartz
 */
public class PersistentSessionsWorker {
    private static final Logger LOG = Logger.getLogger(PersistentSessionsWorker.class);

    private final KeycloakSessionFactory factory;
    private final ArrayBlockingQueue<PersistentUpdate> asyncQueuePersistentUpdate;
    private final int maxBatchSize;
    private final List<Thread> threads = new ArrayList<>();
    private volatile boolean stop;

    public PersistentSessionsWorker(KeycloakSessionFactory factory,
                                    ArrayBlockingQueue<PersistentUpdate> asyncQueuePersistentUpdate, int maxBatchSize) {
        this.factory = factory;
        this.asyncQueuePersistentUpdate = asyncQueuePersistentUpdate;
        this.maxBatchSize = maxBatchSize;
    }

    public void start() {
        threads.add(new BatchWorker(asyncQueuePersistentUpdate));
        threads.forEach(Thread::start);
    }

    private class BatchWorker extends Thread {
        private final ArrayBlockingQueue<PersistentUpdate> queue;

        public BatchWorker(ArrayBlockingQueue<PersistentUpdate> queue) {
            this.queue = queue;
        }

        public void run() {
            Thread.currentThread().setName(this.getClass().getName());
            while (!stop) {
                try {
                    process(queue);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        private void process(ArrayBlockingQueue<PersistentUpdate> queue) throws InterruptedException {
            ArrayList<PersistentUpdate> batch = new ArrayList<>();
            // Timeout is only a backup if interrupting the worker task in the stop() method didn't work as expected because someone else swallowed the interrupted flag.
            PersistentUpdate polled = queue.poll(1, TimeUnit.SECONDS);
            if (polled != null) {
                batch.add(polled);
                queue.drainTo(batch, maxBatchSize - 1);
                KeycloakModelUtils.runJobInTransaction(factory, outerSession -> {
                    TracingProvider tracing = outerSession.getProvider(TracingProvider.class);
                    Tracer process = tracing.getTracer("PersistentSessionsWorker");
                    SpanBuilder spanBuilder = process.spanBuilder("PersistentSessionsWorker.process");
                    if (batch.size() > 1) {
                        batch.stream().map(update -> update.getSpan().getSpanContext()).forEach(spanBuilder::addLink);
                    } else {
                        spanBuilder.setParent(Context.current().with(batch.get(0).getSpan()));
                    }
                    Span span = tracing.startSpan(spanBuilder);
                    try {
                        if (batch.size() > 1) {
                            batch.forEach(persistentUpdate -> {
                                persistentUpdate.getSpan().addLink(span.getSpanContext());
                            });
                        }
                        LOG.debugf("Processing %d deferred session updates.", batch.size());
                        Retry.executeWithBackoff(iteration -> {
                                    if (iteration < 2) {
                                        // attempt to write whole batch in the first two attempts
                                        KeycloakModelUtils.runJobInTransaction(factory,
                                                innerSession -> batch.forEach(c -> c.perform(innerSession)));
                                        batch.forEach(PersistentUpdate::complete);
                                    } else {
                                        LOG.warnf("Running single changes in iteration %d for %d entries", iteration, batch.size());
                                        ArrayList<PersistentUpdate> performedChanges = new ArrayList<>();
                                        List<Throwable> throwables = new ArrayList<>();
                                        batch.forEach(change -> {
                                            try {
                                                KeycloakModelUtils.runJobInTransaction(factory,
                                                        change::perform);
                                                change.complete();
                                                performedChanges.add(change);
                                            } catch (Throwable ex) {
                                                throwables.add(ex);
                                            }
                                        });
                                        batch.removeAll(performedChanges);
                                        if (!throwables.isEmpty()) {
                                            RuntimeException ex = new RuntimeException("unable to complete some changes");
                                            throwables.forEach(ex::addSuppressed);
                                            throw ex;
                                        }
                                    }
                                },
                                Duration.of(10, ChronoUnit.SECONDS), 0);
                    } catch (RuntimeException ex) {
                        tracing.error(ex);
                        batch.forEach(o -> o.fail(ex));
                        LOG.warnf(ex, "Unable to write %d deferred session updates", batch.size());
                    } finally {
                        tracing.endSpan();
                    }
                });
            }
        }
    }

    public void stop() {
        stop = true;
        threads.forEach(Thread::interrupt);
        threads.forEach(t -> {
            try {
                t.join(TimeUnit.MINUTES.toMillis(1));
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
