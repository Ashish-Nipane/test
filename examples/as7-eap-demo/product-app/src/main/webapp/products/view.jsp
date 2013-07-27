<%@ page import="javax.ws.rs.core.*" language="java" contentType="text/html; charset=ISO-8859-1"
 pageEncoding="ISO-8859-1"%>
<html>
<head>
    <title>Product View Page</title>
</head>
<body bgcolor="#F5F6CE">
<%
   String logoutUri = UriBuilder.fromUri("http://localhost:8080/auth-server/rest/realms/demo/tokens/logout")
                                     .queryParam("redirect_uri", "http://localhost:8080/product-portal").build().toString();
%>

<p>Goto: <a href="http://localhost:8080/customer-portal">customers</a> | <a href="<%=logoutUri%>">logout</a></p>
User <b><%=request.getUserPrincipal().getName()%></b> made this request.
<h2>Product Listing</h2>
<%
java.util.List<String> list = org.jboss.resteasy.example.oauth.ProductDatabaseClient.getProducts(request);
for (String cust : list)
{
   out.print("<p>");
   out.print(cust);
   out.println("</p>");

}
%>
<br><br>
</body>
</html>