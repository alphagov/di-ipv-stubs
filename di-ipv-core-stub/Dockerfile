FROM openjdk:17-jdk-slim AS build

WORKDIR /home/gradle/src
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
RUN ./gradlew build --no-daemon
COPY src src
RUN ./gradlew build --no-daemon

FROM openjdk:17-jdk-slim

ENV PORT 8085
ENV DEBUG_PORT 8087
ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:$DEBUG_PORT
RUN addgroup --system --gid 1001 appgroup && adduser --system --uid 1001 appuser --gid 1001
RUN mkdir /app
RUN apt-get update && apt-get install -y curl
COPY --from=build \
	/home/gradle/src/build/distributions/src.tar \
	/app/

WORKDIR /app

RUN tar -xvf src.tar \
	&& rm src.tar

RUN chown -R appuser:appgroup /app/
USER appuser
EXPOSE $PORT
EXPOSE $DEBUG_PORT

ENTRYPOINT ["./src/bin/src"]
LABEL project="di-ipv-core-stub"
