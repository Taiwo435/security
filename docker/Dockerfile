FROM opensearchproject/opensearch:latest

# Remove the existing security plugin
RUN /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security

# Copy our custom plugin ZIP
COPY build/distributions/opensearch-security-3.8.0.0-SNAPSHOT.zip /tmp/security-plugin.zip

# Patch version to match this image, then install
RUN mkdir -p /tmp/plugin-extract && \
    cd /tmp/plugin-extract && \
    unzip /tmp/security-plugin.zip && \
    sed -i 's/opensearch.version=3.8.0/opensearch.version=3.7.0/' plugin-descriptor.properties && \
    zip -r /tmp/patched-plugin.zip . && \
    /usr/share/opensearch/bin/opensearch-plugin install --batch file:///tmp/patched-plugin.zip && \
    rm -rf /tmp/plugin-extract /tmp/security-plugin.zip /tmp/patched-plugin.zip
