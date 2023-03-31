FROM kalilinux/kali-last-release:latest

WORKDIR /app

COPY . ./

RUN apt update && apt install golang-go jadx dex2jar -y

RUN go build apkhunt.go

ENTRYPOINT ["/app/apkhunt"]