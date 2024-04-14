FROM alpine:3.19
WORKDIR /app/
RUN apk add --update --no-cache                         \
        python3~=3.11                                   \
        py3-pip~=23                                     \
        socat~=1.8                                   && \
    pip install --no-cache-dir --break-system-packages  \
        pycryptodome==3.20.0                            \
        inputimeout==1.0.4                           && \
    chown guest: /usr/bin/socat                      && \
    chmod 500 /usr/bin/socat
EXPOSE 4000
COPY --chown=guest:guest --chmod=500 ./src/sniffer.py ./
COPY --chown=guest:guest --chmod=500 ./src/client.py ./
COPY --chown=guest:guest --chmod=500 ./src/server.py ./
COPY --chown=guest:guest --chmod=500 ./src/common.py ./
COPY --chown=guest:guest --chmod=400 ./src/data/server_public_key.der ./data/
COPY --chown=guest:guest --chmod=400 ./src/data/server_private_key.der ./data/
COPY --chown=guest:guest --chmod=400 ./src/data/flag.txt ./data/
USER guest
#ENV DEBUG=1
CMD ["socat", "tcp-listen:4000,reuseaddr,fork", "exec:timeout -s KILL 300 python3 -u /app/sniffer.py"]
