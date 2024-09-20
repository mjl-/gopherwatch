build: build0 index.js
	CGO_ENABLED=0 go build

build0:
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet
	CGO_ENABLED=0 go run vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none API >api.json
	./gents.sh api.json api.ts

race: build0
	go build -race

test:
	CGO_ENABLED=0 go test -shuffle=on -coverprofile cover.out
	go tool cover -html=cover.out -o cover.html

test-race:
	CGO_ENABLED=1 go test -shuffle=on -race -coverprofile cover.out
	go tool cover -html=cover.out -o cover.html

run: build
	./gopherwatch serve

run-mox: build
	./gopherwatch serve -config gopherwatch-mox.conf

run-resettree: build
	./gopherwatch serve -resettree

run-resettree-mox: build
	./gopherwatch serve -resettree -config gopherwatch-mox.conf

mox:
	mox localserve -dir local/mox

genconf: build
	./gopherwatch genconf >new.conf

check:
	GOARCH=386 CGO_ENABLED=0 go vet
	CGO_ENABLED=0 staticcheck

check-shadow:
	go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

index.js: api.ts lib.ts index.ts node_modules/.bin/tsc
	./tsc.sh index.js api.ts lib.ts index.ts

tswatch:
	bash -c 'while true; do inotifywait -q -e close_write *.ts; make index.js; done'

node_modules/.bin/tsc:
	-mkdir -p node_modules/.bin
	npm ci --ignore-scripts

installjs:
	-mkdir -p node_modules/.bin
	npm ci --ignore-scripts

installjs0:
	-mkdir -p node_modules/.bin
	npm install --ignore-scripts --save-dev --save-exact typescript@5.1.6

fmt:
	go fmt ./...
	gofmt -w -s *.go
