# digpcap - produces 'dig' style output from a tcpdump 'pcap' file

This uility reads packet captures files, such as those produced
by Wireshark or tcpdump, and prints any DNS information found
in those files. The output format is in the standard "presentation"
format, the format produced by 'dig' and which can be read by
DNS servers.

Example:

    $ digpcap sample.pcap
    twitter.com.            759     IN      A       104.244.42.1
    twitter.com.            759     IN      A       104.244.42.193
    api.twitter.com.        1190    IN      A       104.244.42.66
    api.twitter.com.        1190    IN      A       104.244.42.130
    api.twitter.com.        1190    IN      A       104.244.42.194
    api.twitter.com.        1190    IN      A       104.244.42.2
    pbs.twimg.com.          242     IN      CNAME   cs196.wac.edgecastcdn.net.
    cs196.wac.edgecastcdn.net. 3115    IN   CNAME   cs2-wac.apr-8315.edgecastdns.net.
    cs2-wac.apr-8315.edgecastdns.net. 299     IN    CNAME   cs2-wac-us.8315.ecdns.net.
    cs2-wac-us.8315.ecdns.net. 299     IN   CNAME   cs45.wac.edgecastcdn.net.
    cs45.wac.edgecastcdn.net. 89      IN    A       72.21.91.70
    abs.twimg.com.          174     IN      CNAME   cs196.wac.edgecastcdn.net.
    cs196.wac.edgecastcdn.net. 30      IN   CNAME   cs2-wac.apr-8315.edgecastdns.net.
    cs2-wac.apr-8315.edgecastdns.net. 299     IN    CNAME   cs2-wac-us.8315.ecdns.net.
    cs2-wac-us.8315.ecdns.net. 299     IN   CNAME   cs45.wac.edgecastcdn.net.
    cs45.wac.edgecastcdn.net. 1434    IN    A       72.21.91.70
    t.co.                   1521    IN      A       104.244.42.5
    t.co.                   1521    IN      A       104.244.42.197

