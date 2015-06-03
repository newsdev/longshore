all: bin/longshore

release: bin/longshore
	aws s3 cp bin/longshore s3://newsdev-pub/bin/longshore

bin/longshore: bin
	docker build -t longshore-build $(CURDIR) && docker run --rm -v $(CURDIR)/bin:/opt/bin longshore-build cp /go/bin/longshore /opt/bin/longshore && docker rmi longshore-build

bin:
	mkdir -p bin

clean:
	rm -rf bin
