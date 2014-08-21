# This Branch:

- Refactored AuthManager and SessionManagers so that any identity provider / Session data handler can be used
- Added SessionExpiry to AdpiDefinition, keys can expire on a date, and can be dropped form a session store set by this value, this increases security as re-auth can be forced with this
- Enables switching out storage managers per identity or session provider, so now it is fully mix and match