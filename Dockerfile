# Start from the official Golang image
FROM golang:1.18-bullseye

# Install necessary tools
RUN apt-get update && apt-get install -y \
    grep \
    wget \
    unzip \
    openjdk-11-jdk \
    && rm -rf /var/lib/apt/lists/*

# Install jadx
RUN wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    && unzip jadx-1.5.0.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm jadx-1.5.0.zip

# Install dex2jar
RUN wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip \
    && unzip dex-tools-v2.4.zip \
    && mv dex-tools-v2.4 /opt/ \
    && ln -s /opt/dex-tools-v2.4/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar \
    && chmod +x /opt/dex-tools-v2.4/*.sh \
    && rm dex-tools-v2.4.zip

# Set the working directory in the container
WORKDIR /app

# Copy the source code
COPY . .

# Declare a volume for APK files
VOLUME /apk

# Command to run the Go script
CMD ["go", "run", "apkhunt.go"]
