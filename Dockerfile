FROM kalilinux/kali-last-release:latest

WORKDIR /app

COPY . ./

RUN apt update && apt install golang-go ca-certificates openssl make -y
RUN update-ca-certificates

RUN make dependencies
RUN make compile

ENTRYPOINT ["/app/apkhunt"]