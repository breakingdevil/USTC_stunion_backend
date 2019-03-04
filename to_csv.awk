#!/usr/bin/awk -f
BEGIN {
    started = 0
}
/^Query results for ".*\.sql":?/ {
    if (started == 0) {
        started == 1
    } else {
        ORS = "\n";
        print ""
    }
    OFS = "-"
    ORS = ","
    match($4, /\d{8}-\d{6}/, m)
    print m
}
/^Query "\w+\.sql"$/ {
    match($2, /"(\w+)\.sql"/, m)
    switch (m[1]) {
        case "user_count":
            mode = 1
            break
        case "user_type":
            mode = 2
            break
        case "wish_status":
            mode = 3
            break
        case "love_count":
            mode = 4
            break
        default:
            mode = 0
            break
    }
}
END {
}
