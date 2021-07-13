FROM public.ecr.aws/lts/ubuntu:20.04

RUN apt-get update && apt-get install -y ca-certificates

COPY docker/runner/runner .
COPY build/bin /app
COPY build/lib /app/lib

ENV APP_BINARY=/app/mqtt_demo_mutual_auth
ENV LD_LIBRARY_PATH=/app/lib

ENV ROOT_CA_CERT_PATH=/app/certificates/AmazonRootCA1.crt
ENV CLIENT_CERT_PATH=/app/certificates/Alpha-Demo-1.cert.pem
ENV CLIENT_CERT_KEY_PATH=/app/certificates/Alpha-Demo-1.public.key
ENV CLIENT_PRIVATE_KEY_PATH=/app/certificates/Alpha-Demo-1.private.key
ENV MQTT_EXAMPLE_TOPIC=Alpha-Demo-Topic

ENTRYPOINT ["/runner"]
