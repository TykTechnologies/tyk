package main

/*
TODO:
1. Need to store OAuth client app registrations:
	- Client ID
	- Client Secret
	- Client redirect URI

2. Need to provide generic endpoints for Proxy API's to integrate with:
	a. {{api_id}}/oauth/authorize -> Called after login on API provider integration page, returns JSON
	   of auth_code, oauth_token and redirect URI for the provider to send the user to (client redirect URI)
	b. {{api-_id}}/oauth/{{oauth_token}} -> Returns key data (same as other key retrieval, just managed)

3. Need to provide generic access endpoints for Client systems to work with:
	a. {{api_id}}/oauth/token -> Called by client app with auth_code to retrieve oauth_token and refresh_token

4. Update the Api Definition object to include an UseOauth2 flag - this will force auth_header retrieval to use the correct
   header name. This will need to b different as we will only support Bearer codes.
   	a. OAuth needs a few extra options if enabled:
   		1. Add a RefreshNotifyHook string to notify resource of refreshed keys
   		2. EnableRefreshTokens -> Basically disallows auth_code requests
   		3. Authentication URL -> URL to redirect the user to

5. Requires a webhook handler to notify resource provider when an oauth token is updated through refresh (POSTs old_oauth_token,
   new_oauth_token - will do so until it receives a 200 OK response or max 3 times).

IDea:
-----
1. Request to /authorize
2. Tyk extracts all relevant data and pre-screens client_id, client_secret and redirect_uri
3. Instead of proxying the request it redirects the user to the login page on the resource
4. Resource presents approve / deny window to user
5. If approve is clicked, resource pings oauth/generate which is the actual authorize endpoint (requires admin key),
   this returns oauth details to resource as well as redirect URI
6. User is redirected to redirect URI with auth_code
7. Client API makes all calls with bearer token

Effort required by Resource Owner:
1. Create a login & approve/deny page
2. Send an API request to Tyk to generate OAuth creds & store oauth key against identity
3. Create an endpoint for tyk to ping when a refresh request comes in with the old and new oauth keys (optional)

*/
