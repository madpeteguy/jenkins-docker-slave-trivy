FROM madpeteguy/jenkins-docker-slave-ssh:1.4.0

LABEL maintainer="Mad Pete Guy"

# Update and install git.
ENV DEBIAN_FRONTEND=noninteractive

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.49.1 && \
    mkdir -p contrib && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/html.tpl > contrib/html.tpl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/junit.tpl > contrib/junit.tpl

COPY imgdata /opt

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
