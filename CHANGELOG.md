# Changes in dev version:

- Refactored AuthManager and SessionManagers so that any identity provider / Session data handler can be used
- Added SessionExpiry to AdpiDefinition, keys can expire on a date, and can be dropped form a session store set by this value, this increases security as re-auth can be forced with this
- Enables switching out storage managers per identity or session provider, so now it is fully mix and match
- API Requests require an api_id form value (either param or body) as keys are now stored (federated) on a per API basis and can live in multiple stores. THIS IS A BREAKING CHANGE
- Will not work with Dashboard 0.7, don't even try it... will be updated separately.