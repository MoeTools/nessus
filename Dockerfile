FROM almalinux:8

RUN dnf makecache && \
  dnf install -y hostname platform-python-setuptools python3-pip && \
  python3 -m pip install --no-cache-dir supervisor supervisor-stdout && \
  curl -fsSL -o /usr/local/lib/python3.6/site-packages/supervisor_stdout.py https://cdn.jsdelivr.net/gh/coderanger/supervisor-stdout@master/supervisor_stdout.py && \
  mkdir /var/log/supervisor/ && \
  dnf install -y https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.4.1-es8.x86_64.rpm && \
  dnf clean all  && rm -rf /var/cache/dnf/*

COPY supervisord.conf /etc/supervisord.conf
COPY configure_scanner.py /opt/scripts/configure_scanner.py

ENV PORT 8834
EXPOSE $PORT/tcp

VOLUME ["/opt/nessus"]

CMD ["supervisord", "-c", "/etc/supervisord.conf"]