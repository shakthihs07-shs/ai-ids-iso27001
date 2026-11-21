# The fixed CICFlowMeter of KU Leuven DistriNet (Engelen et al., WTMC 2021; Liu et al., CNS 2022), built from
# source at a pinned commit: it computes the same flow features the detector was trained on.
# It bundles log4j-core 2.11.0 (Log4Shell). run-hourly.sh therefore runs it without network, read-only and with
# message lookups disabled; it only reads packet captures offline.
FROM alpine:3.20 AS build
RUN apk add --no-cache git openjdk8 libpcap-dev unzip
ARG COMMIT=4dd5319ad36457010d7a406505790b17a5828108
RUN git clone --quiet https://github.com/GintsEngelen/CICFlowMeter /src && git -C /src checkout --quiet "$COMMIT"
WORKDIR /src
# The zip Gradle just built holds some files twice, which trips unzip's zip-bomb check and its replace prompt;
# the authors' Dockerfile also disables the check and overwrites (-o)
RUN ./gradlew --no-daemon --quiet distZip \
    && UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE unzip -o -q build/distributions/CICFlowMeter-*.zip -d /dist \
    && mv /dist/CICFlowMeter-* /dist/cfm

FROM alpine:3.20
RUN apk add --no-cache openjdk8-jre libpcap-dev
COPY --from=build /dist/cfm /opt/cfm
# The cfm launcher finds the jnetpcap native library relative to its own directory
WORKDIR /opt/cfm/bin
ENV JAVA_OPTS="-Xmx384m -Dlog4j2.formatMsgNoLookups=true"
ENTRYPOINT ["./cfm"]
