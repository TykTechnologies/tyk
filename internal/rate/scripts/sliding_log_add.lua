local key = KEYS[1]

local now_str = ARGV[1]
local window_start_str = ARGV[2]
local max_allowed = tonumber(ARGV[3])
local per_seconds = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start_str)

local count = redis.call('ZCARD', key)

redis.call('ZADD', key, now_str, now_str)
redis.call('EXPIRE', key, per_seconds)

local remaining = max_allowed - count - 1
if remaining < 0 then
	remaining = 0
end

local earliest_next = now_str
if count >= max_allowed then
    local oldest = redis.call('ZRANGE', key, -max_allowed, -max_allowed)
    if #oldest > 0 then
        earliest_next = oldest[1]
    end
end

return { count, remaining, earliest_next }