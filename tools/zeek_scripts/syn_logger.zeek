event connection_attempt(c: connection)
{
    if (c$proto == tcp && c$history == "S") {
        print fmt("SYN from %s:%s → %s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}
