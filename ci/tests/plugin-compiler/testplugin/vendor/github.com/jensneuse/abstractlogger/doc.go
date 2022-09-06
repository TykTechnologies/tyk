/*
package abstractlogger solves the problem of abstracting away a logging frontend from a logging backend.

Usually you would choose the best logger you can for your project.
This can be determined by specific needs regarding the interface of the logger or just requirements regarding performance.

But what if you want to change the logger easily?
What if you're building a library and want your users to be able to use whatever logging library they want?

This is exactly the problem abstractlogger tries to solve.
This package acts as a "frontend" for logging that lets you or your users choose the backend.

You're free to use one of the existing implementations, e.g. zap or logrus which are common across the community.
If that doesn't satisfy your needs feel free to implement the interface yourself.
You're invited to contribute back your additional implementations.

If you think the Logger interface/frontend doesn't satisfy your needs feel free to add additional funcs via a PR.
*/
package abstractlogger
