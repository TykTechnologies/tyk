```
docker run -d --name keycloak -v ./keycloak/data:/opt/keycloak/data/h2  -p 8081:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -e KC_FEATURES=preview  quay.io/keycloak/keycloak:23.0.6 start-dev --features=preview
```

```mermaid
sequenceDiagram
    participant C as Client
    participant AS as Authorization Server
    participant RS as Resource Server

    C->>+AS: Request Access Token (Client Credentials)
    AS->>-C: Access Token
    C->>+RS: Request Protected Resource (Access Token)
    RS->>-C: Protected Resource
```

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client
    participant AS as Authorization Server
    participant RS as Resource Server

    U->>C: Access Application
    C->>U: Redirect to Authorization Server
    U->>AS: Authenticate & Authorize Application
    AS->>U: Authorization Code
    U->>C: Redirect with Authorization Code
    C->>AS: Exchange Authorization Code for Access Token
    AS->>C: Access Token (& Refresh Token)
    C->>RS: Access Protected Resources with Access Token
    RS->>C: Protected Resources

```

```mermaid
graph TD;
    A[Client] -->|1. Initiate Authorization| B[Authorization Server];
    B -->|2. Redirect to Login| C[User];
    C -->|3. Provide Credentials| B;
    B -->|4. Authorization Grant| A;
    A -->|5. Authorization Code| B;
    B -->|6. Authorization Code| D[Token Endpoint];
    D -->|7. Authorization Code| B;
    B -->|8. Access Token| A;
    A -->|9. Access Protected Resource| E[Resource Server];
    E -->|10. Access Token| A;
    A -->|11. Protected Resource| E;
```

```mermaid
sequenceDiagram
    participant C as Client
    participant AS as Authorization Server
    participant RS as Resource Server

    Note over C,AS: The client already has an initial token

    C->>+AS: Request Token Exchange<br/>(Includes initial token and requested scopes)
    AS->>-C: Validates Request<br/>(Authentication and Authorization)
    alt Successful Validation
        AS->>+C: Issue new token<br/>(Access token with optional Refresh token)
    else Validation Failure
        AS->>+C: Error Response<br/>(Invalid Request or Unauthorized)
    end
    opt Access Protected Resource
        C->>+RS: Request Resource with New Token
        RS->>-C: Protected Resource
    end
```



```mermaid
sequenceDiagram
    participant Client
    participant AS as Authorization Server
    participant Tyk as Ingress Gateway
    

    Client->>AS: Authorize
    note left of AS: POST /token<br />grant_type=authorization_code<br />client_id=external-app
    AS->>Client: AccessToken foo.bar.baz
    note left of AS: aud: gateway
    Client->>Tyk: GET: /account -H 'authorization: Bearer foo.bar.baz'
    create participant JWTMW as JWT Middleware
    Tyk->>JWTMW: forward request to mw
    JWTMW->JWTMW: Validate JWT
    note left of JWTMW: JWT is valid
    destroy JWTMW
    JWTMW->>Tyk: return OK
    create participant TokenExchangeMW as Token Exchange Middleware
    Tyk->>TokenExchangeMW: forward request to mw
    TokenExchangeMW->>AS: POST /token
    note left of TokenExchangeMW: <br />grant_type=urn:ietf:params:oauth:grant-type:token-exchange<br />client_id=gateway<br />client_secret=gateway_secret<br />subject_token=foo.bar.baz
    AS->>TokenExchangeMW: AccessToken baz.bar.foo
    note right of AS: azp: gateway<br />aud: microservice
    TokenExchangeMW->>TokenExchangeMW: Replace access token in request header
    destroy TokenExchangeMW
    TokenExchangeMW->>Tyk: return OK
    participant MS as Microservice
    Tyk->>MS: reverse proxy to microservice
    MS->>Tyk: return response
    Tyk->>Client: return response
```
