# Passport with JWT
- click [here](https://jwt.io/) to know more about JWT
## Structure of JWT
- Header
- Payload
- Signature

### Header
- header contains two fields
    - alg: which algorithm we are using to create the digital signature, eg. RS256, HS512
    - typ: which is type of token, eg. JWT

### Payload
- It is meta-deta about some entity
- In most cases it is going to be about some user 
- **NEVER** put sensitive info in **payload**
- Click [here](https://datatracker.ietf.org/doc/html/rfc7519) to know more about JWT claims

### Signature
- The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way. 
- To create the signature, the **Base64-encoded** header and payload are taken, along with a secret, and signed with the algorithm specified in the header.
## Client Server interaction

![client-server-interaction](/assets/client-server-interaction.png)

## Ways to implement JWT authentication in our app
### Most Complext
- Use the Node JS crypto library and wirte our own middleware to sign and verify JWTs
### Somewhat Complext
- Use the jsonwebtoken NPM module and write our own middleware

### Least Complex
- Use the jsonwebtoken NPM module and use passport-jwt as our middleware

## JWT authentication process
- The user logs in to web app, and is issued a JSON Web Token (JWT)
- User client (usually a browser like Google Chrome) stores the JWT in `local storage` or a `Cookie`
- On every HTTP request that requires authentication, the user client (browser) will attach the JWT in the `Authorization` HTTP header and verifies the signature
- If the signature is valid, the server dcodes the JWT, usually gets the database ID of the user in the `payload.sub` field, looks the user up in the database, and stores the use object to sue.
- The user receives the route data