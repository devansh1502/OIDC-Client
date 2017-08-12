# BootCamp-Project
This Project is about creating a java spring code for OIDC.
OIDC is a simple identity layer on top of OAuth 2.0 Protocol. It enables client to verify the identity of End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User.OpenID Connect lets registered clients authenticate their users across websites and apps without having to own and manage password files. For the application builder, it provides a secure verifiable, answer to the question: “What is the identity of the person currently using the browser or native application that is connected to me?” 

In this Project, the client will be entering all the necessary details like the auhtorization token endpoint, token endpoint, token keys endpoint ,client id ,client secret & scope.

The data will be stored in a session and it will redirect to the client site for authentication.
After the authentication is done. An exchange code will be generated and that code will be used to get an id token.
Further, that id token will be validated using libraries.
This whole process is known as Authorisation Code Flow.

Implicit flow for the same project will be implemented after authorisation code flow is done.
