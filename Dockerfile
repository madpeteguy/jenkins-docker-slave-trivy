FROM madpeteguy/jenkins-docker-slave-ssh:1.4.1

LABEL maintainer="Mad Pete Guy"

ENV DEBIAN_FRONTEND=noninteractive

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.53.0 && \
    mkdir -p contrib && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/html.tpl > contrib/html.tpl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/junit.tpl > contrib/junit.tpl

COPY imgdata /opt

ENV TRIVY_CACHE_DIR=/trivy_cache

VOLUME ["$TRIVY_CACHE_DIR"]

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
