
ARG VERSION_MERGER=1.0.8
ARG ARTIFACTORY_URL=https://repo.orl.eng.hitachivantara.com/artifactory/pnt-mvn

RUN curl -L -o version-merger.jar ${ARTIFACTORY_URL}/pentaho/version-merger/${VERSION_MERGER}/version-merger-${VERSION_MERGER}.jar

RUN curl -fL https://install-cli.jfrog.io | sh

ARG JQ_VERSION=1.6
RUN curl -L -o jq-linux64 https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64 && \
    mv jq-linux64 /usr/local/bin/jq && \
    chmod +x /usr/local/bin/jq

# pip
RUN apt-get update && \
    apt-get install -y python3-pip python3.11-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install PyYAML
RUN pip install pyyaml
