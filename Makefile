build: build0
	CGO_ENABLED=0 go build

build0:
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet
	CGO_ENABLED=0 go run vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none API >api.json
	./gents.sh api.json api.ts

race: build0
	go build -race

testmode: build
	./gopherwatch serve -testlog

livemode: build
	./gopherwatch serve

livemode-mox: build
	./gopherwatch serve -config gopherwatch-mox.conf

livemode-resettree: build
	./gopherwatch serve -resettree

livemode-resettree-mox: build
	./gopherwatch serve -resettree -config gopherwatch-mox.conf

mox:
	mox localserve -dir local/mox

genconf: build
	./gopherwatch genconf >new.conf

check:
	GOARCH=386 CGO_ENABLED=0 go vet
	staticcheck

check-shadow:
	go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

index.js: api.ts lib.ts index.ts
	./tsc.sh $@ $^

jswatch:
	bash -c 'while true; do inotifywait -q -e close_write *.ts; make index.js; done'

jsinstall:
	-mkdir -p node_modules/.bin
	npm ci --ignore-scripts

jsinstall0:
	-mkdir -p node_modules/.bin
	npm install --ignore-scripts --save-dev --save-exact typescript@5.1.6

fmt:
	go fmt ./...
	gofmt -w -s *.go
