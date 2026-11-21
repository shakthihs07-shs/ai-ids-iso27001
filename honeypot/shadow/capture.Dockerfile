# Records packets to and from the honeypot's fake services only (never the tracker on 443 or admin SSH on 22022),
# in hourly files that run-hourly.sh turns into flows and then deletes.
FROM alpine:3.20
RUN apk add --no-cache tcpdump iproute2
COPY capture.sh /capture.sh
ENTRYPOINT ["sh", "/capture.sh"]
