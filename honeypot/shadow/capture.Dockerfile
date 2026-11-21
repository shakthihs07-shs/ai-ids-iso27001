# Records packets to and from the honeypot's fake services only (never the tracker on 443 or admin SSH on 22022),
# in hourly files that run-hourly.sh turns into flows and then deletes. tcpdump opens the interface as root and
# then runs as its own unprivileged user, which owns the capture folder.
FROM alpine:3.20
RUN apk add --no-cache tcpdump iproute2 && (id tcpdump || adduser -S -D -H tcpdump) \
    && mkdir /pcap && chown tcpdump /pcap && chmod 700 /pcap
COPY capture.sh /capture.sh
ENTRYPOINT ["sh", "/capture.sh"]
