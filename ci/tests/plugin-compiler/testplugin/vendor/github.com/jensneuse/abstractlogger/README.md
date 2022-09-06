# abstractlogger

Abstractlogger is a logging frontend to abstract away logging from your frontend of choice.

Abstractlogger enables you to use your logging backend of choice.
Currently there's a zap and logrus implementation.
Feel free to add additional logging backend implementations.

You should consider using abstract logger in two situations:
1. You're building a library and don't want to make the choice for your user on which logging backend to use.
2. You're building an application and want logging in the hot path. You're unsure which logging library to use. In this case Abstractlogger helps you to keep your domain logic separated from a 3rd party logging library as you can change it every time without updating all of your code.

If you feel an important logging method is missing please file an issue or create a PR.
Tested code is welcomed.

## Benchmarks

```text
BenchmarkNoopLogger/with_interface/log_level_invalid/noop-16    	15396679	        84.4 ns/op	     448 B/op	       2 allocs/op
BenchmarkNoopLogger/with_interface/log_level_invalid/logrus-16  	 2463068	       486 ns/op	    1938 B/op	      14 allocs/op
BenchmarkNoopLogger/with_interface/log_level_invalid/zap-16     	13834630	        85.3 ns/op	     352 B/op	       2 allocs/op
BenchmarkNoopLogger/with_interface/log_level_invalid/abstract_zap-16         	50709734	        24.4 ns/op	      96 B/op	       1 allocs/op
BenchmarkNoopLogger/with_interface/log_level_invalid/abstract_logrus-16      	48983234	        23.2 ns/op	      96 B/op	       1 allocs/op
BenchmarkNoopLogger/with_interface/log_level_valid/noop-16                   	14264962	        81.6 ns/op	     448 B/op	       2 allocs/op
BenchmarkNoopLogger/with_interface/log_level_valid/logrus-16                 	  158092	      6919 ns/op	    3401 B/op	      44 allocs/op
BenchmarkNoopLogger/with_interface/log_level_valid/zap-16                    	 4579869	       277 ns/op	     434 B/op	       3 allocs/op
BenchmarkNoopLogger/with_interface/log_level_valid/abstract_zap-16           	 3741235	       325 ns/op	     434 B/op	       3 allocs/op
BenchmarkNoopLogger/with_interface/log_level_valid/abstract_logrus-16        	  157494	      6822 ns/op	    2433 B/op	      40 allocs/op
BenchmarkNoopLogger/without_interface/log_level_invalid/noop-16              	18548176	        62.5 ns/op	     288 B/op	       1 allocs/op
BenchmarkNoopLogger/without_interface/log_level_invalid/logrus-16            	 3592113	       380 ns/op	    1393 B/op	      10 allocs/op
BenchmarkNoopLogger/without_interface/log_level_invalid/zap-16               	23941255	        48.3 ns/op	     192 B/op	       1 allocs/op
BenchmarkNoopLogger/without_interface/log_level_invalid/abstract_zap-16      	250681747	         5.14 ns/op	       0 B/op	       0 allocs/op
BenchmarkNoopLogger/without_interface/log_level_invalid/abstract_logrus-16   	238591336	         4.96 ns/op	       0 B/op	       0 allocs/op
BenchmarkNoopLogger/without_interface/log_level_valid/noop-16                	16967037	        67.3 ns/op	     288 B/op	       1 allocs/op
BenchmarkNoopLogger/without_interface/log_level_valid/logrus-16              	  180975	      6104 ns/op	    2742 B/op	      38 allocs/op
BenchmarkNoopLogger/without_interface/log_level_valid/zap-16                 	10197316	       126 ns/op	     192 B/op	       1 allocs/op
BenchmarkNoopLogger/without_interface/log_level_valid/abstract_zap-16        	 8566719	       145 ns/op	     192 B/op	       1 allocs/op
BenchmarkNoopLogger/without_interface/log_level_valid/abstract_logrus-16     	  178683	      5900 ns/op	    2224 B/op	      37 allocs/op
```

The library improves the performance for non valid log levels by ~10x (zap) and ~76x (logrus).
For valid log levels the overhead is minimal: No additional allocations, 13% increase (145ns vs. 126ns) for zap without using Any.