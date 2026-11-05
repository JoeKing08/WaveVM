# Sum the latest successful-completion counters for this admitted VM only.
/\[WVM-MEM-STATS\]/ {
    delete value
    for (i = 1; i <= NF; i++) {
        split($i, pair, "=")
        if (length(pair[1]) && length(pair[2])) value[pair[1]] = pair[2]
    }
    if ("x" value["vm"] != "x" vm || "x" value["incarnation"] != "x" incarnation ||
        "x" value["manifest"] != "x" manifest ||
        value["origin"] !~ /^[0-9]+$/ ||
        value["instance"] !~ /^[0-9]+$/ ||
        value["runtime"] !~ /^[0-9]+$/ || value["pid"] !~ /^[0-9]+$/ ||
        value["remote_reads"] !~ /^[0-9]+$/ ||
        value["remote_commits"] !~ /^[0-9]+$/ ||
        ("x" value["origin"] == "x" value["directory"] &&
         "x" value["instance"] == "x" value["directory_instance"])) next
    key = value["origin"] SUBSEP value["instance"] SUBSEP value["runtime"] SUBSEP value["pid"]
    latest[key] = value["remote_reads"] + value["remote_commits"]
}
END {
    for (key in latest) total += latest[key]
    print total + 0
}
