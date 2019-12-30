.PHONY=dist clean darwin linux windows
BUILDARGS=-ldflags='-w -s' -trimpath
NAME=ezovpn

all: dist darwin linux windows

clean:
	$(RM) -fvr dist

dist:
	mkdir dist

darwin:
	CGO_ENABLED=0 GOOS=darwin go build ${BUILDARGS} -o dist/${NAME}_macos ./app/${NAME}

linux:
	CGO_ENABLED=0 GOOS=linux go build ${BUILDARGS} -o dist/${NAME}_linux ./app/${NAME}

windows:
	CGO_ENABLED=0 GOOS=windows go build ${BUILDARGS} -o dist/${NAME}_windows ./app/${NAME}
