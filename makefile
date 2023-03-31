CC := go
OPTION := build
SRC := .
BIN := apkhunt

compile:
	$(CC) $(OPTION) -o $(BIN) $(SRC)

clean:
	-rm $(BIN)

dependencies:
	go get github.com/s9rA16Bf4/ArgumentParser
	go get github.com/s9rA16Bf4/notify_handler/go/notify
	apt install golang-go jadx dex2jar -y
	
docker:
	docker build -t apkhunt/apkhunt .