# Helper for building Docker image locally for testing.

all:

build:
	export zeek_packages=$$(cat ../.cirrus.yml | grep zeek_packages: | grep zeek= | cut -d ':' -f 2- | xargs); \
		DOCKER_BUILDKIT=1 docker build --build-arg "zeek_packages=$${zeek_packages}" -t spicy-ci:latest .

run:
	docker run -v $$(cd .. && pwd):/opt/spicy -w /opt/spicy --cap-add SYS_PTRACE -i -t spicy-ci:latest /bin/bash

build-packages:
	DOCKER_BUILDKIT=1 docker build -f Dockerfile.packages -t spicy-ci-packages:latest .

run-packages:
	docker run -v $$(cd .. && pwd):/opt/spicy -w /opt/spicy --cap-add SYS_PTRACE -i -t spicy-ci-packages:latest /bin/bash
