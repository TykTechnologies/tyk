# Changes in dev version:

- Ignored IP's feature added (under analytics_config), adding "ignored_ips" array will cause analytics not to be recorded if coming from specific IP's
- It is now possible to set IP's that shouldn't be tracked by analytics by setting the `ignored_ips` flag in the config file (e.g. for health checks) 
- Many core middleware configs moved into tyk common, tyk common can now be cross-seeded into other apps if necessary and is go gettable.