# About the Example Application

This is a simple application based on HTML5+AngularJS+JAX-RS that will introduce you to some of the main concepts around Keycloak Authorization Services.

Basically, it is a project containing three modules:
 
* **photoz-uma-restful-api**, with a simple RESTFul API based on JAX-RS and acting as a regular **client application**.
* **photoz-uma-html5-client**, with a HTML5+AngularJS client that will consume the RESTful API and acting as a **resource server**.
* **photoz-uma-authz-policy**, with a simple project with some rule-based policies using JBoss Drools.

For this application, users can be regular users or administrators. Regular users can create/view/delete their albums 
and administrators can view the albums for all users.

In Keycloak, albums are resources that must be protected based on a set of policies that defines who and how can access them. 
Beside that, resources belong to a specific resource server, in this case to the *photoz-uma-restful-api*.

The resources are also associated with a set of scopes that define a specific access context. In this case, albums have three main scopes:

* urn:photoz.com:scopes:album:create
* urn:photoz.com:scopes:album:view
* urn:photoz.com:scopes:album:delete

The authorization requirements for this example application are based on the following assumptions:

* By default, any regular user can perform any operation on his resources.

    * For instance, Alice can create, view and delete her albums. 

* Only the owner and administrators can delete albums. Here we are considering policies based on the *urn:photoz.com:scopes:album:delete*

    * For instance, only Alice can delete her album.

* Only administrators can access the Administration API (which basically provides ways to query albums for all users)

That said, this application will show you how to use the Keycloak to define policies using:

* Role-based Access Control
* Attribute-based Access Control
* Rule-based policies using JBoss Drools
* Rule-based policies using JavaScript 

Beside that, this example demonstrates how to create resources dynamically and how to protected them using the *Protection API* and the *Authorization Client API*. Here you'll see
how to create a resource whose owner is the authenticated user.

It also provides some background on how you can actually protect your JAX-RS endpoints using a *policy enforcer*.

## Create the Example Realm and a Resource Server

Considering that your AuthZ Server is up and running, log in to the Keycloak Administration Console.

Now, create a new realm based on the following configuration file:

    examples/authz/photoz/photoz-uma-realm.json
    
That will import a pre-configured realm with everything you need to run this example. For more details about how to import a realm 
into Keycloak, check the Keycloak's reference documentation.

After importing that file, you'll have a new realm called ``photoz``. 

Back to the command-line, build the example application. This step is necessary given that we're using policies based on
JBoss Drools, which require ``photoz-uma-authz-policy`` artifact installed into your local maven repository.

    cd examples/authz/photoz
    mvn clean install 

Now, let's import another configuration using the Administration Console in order to configure the ``photoz-uma-restful-api`` as a resource server with all resources, scopes, permissions and policies.

Click on ``Authorization`` on the left side menu. Click on the ``Create`` button on the top of the resource server table. This will
open the page that allows you to create a new resource server.

Click on the ``Select file`` button, which means you want to import a resource server configuration. Now select the file that is located at:

    examples/authz/photoz/photoz-uma-restful-api/photoz-uma-restful-api-authz-config.json
    
Now click ``Upload`` and a new resource server will be created based on the ``photoz-uma-restful-api`` client application.

## Deploy and Run the Example Applications

To deploy the example applications, follow these steps:

    cd examples/authz/photoz/photoz-uma-html5-client
    mvn wildfly:deploy
    
And then:

    cd examples/authz/photoz/photoz-uma-restful-api
    mvn wildfly:deploy
   
Now, try to access the client application using the following URL:

    http://localhost:8080/photoz-uma-html5-client

If everything is correct, you will be redirect to Keycloak login page. You can login to the application with the following credentials:

* username: jdoe / password: jdoe
* username: alice / password: alice
* username: admin / password: admin


