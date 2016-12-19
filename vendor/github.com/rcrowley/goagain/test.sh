set -e -x

cd "$(dirname "$0")"

findproc() {
    set +x
    find "/proc" -mindepth 2 -maxdepth 2 -name "exe" -lname "$PWD/$1" 2>"/dev/null" |
    cut -d"/" -f"3"
    set -x
}

for NAME in "legacy" "single"
do
    cd "example/$NAME"
    go build
    ./$NAME &
    PID="$!"
    [ "$PID" -a -d "/proc/$PID" ]
    for _ in _ _
    do
        OLDPID="$PID"
        sleep 1
        kill -USR2 "$PID"
        sleep 2
        PID="$(findproc "$NAME")"
        [ ! -d "/proc/$OLDPID" -a "$PID" -a -d "/proc/$PID" ]
    done
    [ "$(nc "127.0.0.1" "48879")" = "Hello, world!" ]
    kill -TERM "$PID"
    sleep 2
    [ ! -d "/proc/$PID" ]
    [ -z "$(findproc "$NAME")" ]
    cd "$OLDPWD"
done

cd "example/double"
go build
./double &
PID="$!"
[ "$PID" -a -d "/proc/$PID" ]
for _ in _ _
do
    sleep 1
    kill -USR2 "$PID"
    sleep 3
    NEWPID="$(findproc "double")"
    [ "$NEWPID" = "$PID" -a -d "/proc/$PID" ]
done
[ "$(nc "127.0.0.1" "48879")" = "Hello, world!" ]
kill -TERM "$PID"
sleep 3
[ ! -d "/proc/$PID" ]
[ -z "$(findproc "double")" ]
cd "$OLDPWD"
