package org.keycloak.events.jpa;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Expression;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.events.admin.OperationType;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class JpaAdminEventQuery implements AdminEventQuery {
    
    private final EntityManager em;
    private final CriteriaBuilder cb;
    private final CriteriaQuery<AdminEventEntity> cq;
    private final Root<AdminEventEntity> root;
    private final ArrayList<Predicate> predicates;
    private Integer firstResult;
    private Integer maxResults;
    
    public JpaAdminEventQuery(EntityManager em) {
        this.em = em;

        cb = em.getCriteriaBuilder();
        cq = cb.createQuery(AdminEventEntity.class);
        root = cq.from(AdminEventEntity.class);
        predicates = new ArrayList<Predicate>();
    }

    @Override
    public AdminEventQuery operation(OperationType... operations) {
        List<String> operationStrings = new LinkedList<String>();
        for (OperationType e : operations) {
            operationStrings.add(e.toString());
        }
        predicates.add(root.get("operationType").in(operationStrings));
        return this;
    }
    
    @Override
    public AdminEventQuery authRealm(String realmId) {
        predicates.add(cb.equal(root.get("authRealmId"), realmId));
        return this;
    }

    @Override
    public AdminEventQuery authClient(String clientId) {
        predicates.add(cb.equal(root.get("authClientId"), clientId));
        return this;
    }

    @Override
    public AdminEventQuery authUser(String userId) {
        predicates.add(cb.equal(root.get("authUserId"), userId));
        return this;
    }

    @Override
    public AdminEventQuery authIpAddress(String ipAddress) {
        predicates.add(cb.equal(root.get("authIpAddress"), ipAddress));
        return this;
    }

    @Override
    public AdminEventQuery resourcePath(String resourcePath) {
        Expression<String> rPath = root.get("resourcePath");
        predicates.add(cb.like(rPath, "%"+resourcePath+"%"));
        return this;
    }

    @Override
    public AdminEventQuery fromTime(String fromTime) {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
        Long from = null;
        try {
            from = df.parse(fromTime).getTime();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        predicates.add(cb.greaterThanOrEqualTo(root.<Long>get("time"), from));
        return this;
    }

    @Override
    public AdminEventQuery toTime(String toTime) {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
        Long to = null;
        try {
            to = df.parse(toTime).getTime();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        predicates.add(cb.lessThanOrEqualTo(root.<Long>get("time"), to));
        return this;
    }

    @Override
    public AdminEventQuery firstResult(int firstResult) {
        this.firstResult = firstResult;
        return this;
    }

    @Override
    public AdminEventQuery maxResults(int maxResults) {
        this.maxResults = maxResults;
        return this;
    }

    @Override
    public List<AdminEvent> getResultList() {
        if (!predicates.isEmpty()) {
            cq.where(cb.and(predicates.toArray(new Predicate[predicates.size()])));
        }

        cq.orderBy(cb.desc(root.get("time")));

        TypedQuery<AdminEventEntity> query = em.createQuery(cq);

        if (firstResult != null) {
            query.setFirstResult(firstResult);
        }

        if (maxResults != null) {
            query.setMaxResults(maxResults);
        }

        List<AdminEvent> events = new LinkedList<AdminEvent>();
        for (AdminEventEntity e : query.getResultList()) {
            events.add(JpaEventStoreProvider.convertAdminEvent(e));
        }

        return events;
    }
        
}
