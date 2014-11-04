Changes v1.1.1
==============

- Path allowances (Ignored / Blacklist / Whitelist) on a version will now happen before an auth check, meaning ignored paths will allow anyone through
- Setting purge_delay to 0 will cause the service to not ever purge the redis DB of analytics data - handy for tyk clusters that only require one node to do the purging