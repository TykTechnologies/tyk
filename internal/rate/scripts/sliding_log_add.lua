local key = KEYS[1]

local max_allowed = tonumber(ARGV[1])
local per_seconds = tonumber(ARGV[2])

-- Redis < 5 needs effects replication to allow writes after TIME.
if redis.replicate_commands then
	redis.replicate_commands()
end

-- Redis server time is the single clock for every gateway sharing this key.
-- Timestamps are built as strings: nanoseconds since epoch exceed Lua's
-- double precision, and members must stay numeric for older gateways.
local t = redis.call("TIME")
local micros = string.format("%06d", tonumber(t[2]))
local now_str = t[1] .. micros .. "000"
local window_start_str = (tonumber(t[1]) - per_seconds) .. micros .. "000"

redis.call("ZREMRANGEBYSCORE", key, "-inf", window_start_str)

local count = redis.call("ZCARD", key)

-- TIME has microsecond resolution, but scripts run one at a time and take
-- longer than that, so two hits never share a microsecond in normal operation.
-- The branch below covers a redis clock stepped backwards (clock_settime,
-- chrony makestep; slewed NTP corrections via adjtimex stay monotonic) and an
-- older gateway writing a nanosecond member here during a rolling upgrade.
-- Every hit of a microsecond is scored with that microsecond, so counting
-- entries with this exact score gives the next free nanosecond suffix.
local member = now_str
local seq = 0
if redis.call("ZADD", key, "NX", now_str, member) == 0 then
	local prefix = now_str:sub(1, -4)
	seq = redis.call("ZCOUNT", key, now_str, now_str)
	member = prefix .. string.format("%03d", seq)

	if seq > 999 or redis.call("ZADD", key, "NX", now_str, member) == 0 then
		redis.log(redis.LOG_WARNING, "sliding log " .. key .. ": no free member at " .. now_str)
		return redis.error_reply("sliding log full at " .. now_str)
	end
end

redis.call("EXPIRE", key, per_seconds)

local remaining = max_allowed - count - 1
if remaining < 0 then
	remaining = 0
end

local earliest_next = now_str
if count >= max_allowed then
	local oldest = redis.call("ZRANGE", key, -max_allowed, -max_allowed)
	if #oldest > 0 then
		earliest_next = oldest[1]
	end
end

return { count, remaining, earliest_next, now_str, seq }
