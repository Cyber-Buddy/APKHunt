FROM kalilinux/kali-last-release:latest

WORKDIR /app

COPY . ./

RUN apt update && apt install golang-go
RUN make dependencies
RUN make build

ENTRYPOINT ["/app/apkhunt"]