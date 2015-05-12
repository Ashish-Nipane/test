package org.keycloak.events.mongo;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.events.admin.OperationType;

import com.mongodb.BasicDBObject;
import com.mongodb.BasicDBObjectBuilder;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;

public class MongoAdminEventQuery implements AdminEventQuery{
    
    private Integer firstResult;
    private Integer maxResults;
    private DBCollection audit;
    private final BasicDBObject query;

    public MongoAdminEventQuery(DBCollection audit) {
        this.audit = audit;
        query = new BasicDBObject();
    }

    @Override
    public AdminEventQuery operation(OperationType... operations) {
        List<String> operationStrings = new LinkedList<String>();
        for (OperationType e : operations) {
            operationStrings.add(e.toString());
        }
        query.put("operationType", new BasicDBObject("$in", operationStrings));
        return this;
    }
    
    @Override
    public AdminEventQuery authRealm(String realmId) {
        query.put("realmId", realmId);
        return this;
    }

    @Override
    public AdminEventQuery authClient(String clientId) {
        query.put("clientId", clientId);
        return this;
    }

    @Override
    public AdminEventQuery authUser(String userId) {
        query.put("userId", userId);
        return this;
    }

    @Override
    public AdminEventQuery authIpAddress(String ipAddress) {
        query.put("ipAddress", ipAddress);
        return this;
    }
    
    @Override
    public AdminEventQuery resourcePath(String resourcePath) {
        query.put("resourcePath", Pattern.compile(resourcePath));
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
        query.put("time", BasicDBObjectBuilder.start("$gte", from).get());
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
        query.put("time", BasicDBObjectBuilder.start("$lte", to).get());
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
        DBCursor cur = audit.find(query).sort(new BasicDBObject("time", -1));
        if (firstResult != null) {
            cur.skip(firstResult);
        }
        if (maxResults != null) {
            cur.limit(maxResults);
        }

        List<AdminEvent> events = new LinkedList<AdminEvent>();
        while (cur.hasNext()) {
            events.add(MongoEventStoreProvider.convertAdminEvent((BasicDBObject) cur.next()));
        }

        return events;
    }
        
}
