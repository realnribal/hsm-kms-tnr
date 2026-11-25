FROM eclipse-temurin:17-jdk-jammy

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        softhsm2 \
        gcc \
        libc6-dev \
        cmake \
        make \
        maven \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
# Prefetch the Surefire provider so the campaign does not download it on first test.
ENV MAVEN_OPTS="-Daether.connector.connectTimeout=20000 -Daether.connector.requestTimeout=60000"
RUN chmod +x scripts/*.sh \
    && mvn -f kms-api/pom.xml -B -DskipTests package \
    && mvn -f kms-api/pom.xml -B org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get \
        -Dartifact=org.apache.maven.surefire:surefire-junit-platform:3.5.3

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["campaign"]
