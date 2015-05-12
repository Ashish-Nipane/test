package org.keycloak.events.admin;

import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface AdminEventQuery {
    
    /**
     * Search by authentication realm
     *
     * @param realm realm name
     * @return Associated <code>AdminEventQuery</code> for method chaining
     */
    AdminEventQuery authRealm(String realm);
    
    /**
     * Search by authenticated client
     *
     * @param client client uuid
     * @return Associated <code>AdminEventQuery</code> for method chaining
     */
    AdminEventQuery authClient(String client);

    /**
     * Search by authenticated user
     *
     * @param user user uuid
     * @return Associated <code>AdminEventQuery</code> for method chaining
     */
    AdminEventQuery authUser(String user);

    /**
     * Search by request ip address
     *
     * @param ipAddress
     * @return Associated <code>AdminEventQuery</code> for method chaining
     */
    AdminEventQuery authIpAddress(String ipAddress);

    /**
     * Search by operation type
     *
     * @param operations
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery operation(OperationType... operations);

    /**
     * Search by resource path. Supports wildcards <code>*</code> and <code>**</code>. For example:
     * <ul>
     * <li><b>*&#47;master</b> - matches 'realms/master'</li>
     * <li><b>**&#47;00d4b16f</b> - matches 'realms/master/clients/00d4b16f'</li>
     * <li><b>realms&#47;master&#47;**</b> - matches anything under 'realms/master'</li>
     * </ul>
     *
     * @param resourcePath
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery resourcePath(String resourcePath);

    /**
     * Search by events after the specified time
     * 
     * @param fromTime time in millis
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery fromTime(String fromTime);

    /**
     * Search by events before the specified time
     * 
     * @param toTime time in millis
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery toTime(String toTime);

    /**
     * Used for pagination
     * 
     * @param first first result to return
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery firstResult(int first);

    /**
     * Use for pagination
     * 
     * @param max the maximum results to return
     * @return <code>this</code> for method chaining
     */
    AdminEventQuery maxResults(int max);

    /**
     * Executes the query and returns the results
     * 
     * @return
     */
    List<AdminEvent> getResultList();

}
