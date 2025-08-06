ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install packages
RUN apk add --no-cache \
    python3 \
    py3-pip

# Install Python packages directly
RUN pip3 install --no-cache-dir --break-system-packages \
    flask \
    requests \
    gunicorn

# Copy rootfs
COPY rootfs /

# Remove any s6 scripts if they exist
RUN rm -rf /etc/services.d /etc/cont-init.d

# Set permissions
RUN chmod a+x /run.sh && \
    chmod a+x /app/*.py || true

# Direct command
CMD [ "/run.sh" ]