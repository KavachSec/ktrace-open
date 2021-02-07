DOCKER_REGISTRY ?= gcr.io/kavach-builds

IMAGE_NAME ?= ktrace
TAG ?= $(shell git rev-parse --short=8 HEAD)

BUILDER_NAME ?= ${IMAGE_NAME}-builder
BUILDER_TAG := $(shell md5sum builder/Dockerfile | awk '{ print $1 }' | head -c 8)

BASE_NAME ?= ${IMAGE_NAME}-base
BASE_TAG := $(shell md5sum base/Dockerfile | awk '{ print $1 }' | head -c 8)

MOUNT_DIR=/ktrace

CC = gcc
CFLAGS = -O2 -Wall -Werror

define run_in_container
	docker run \
		--volume $(realpath .):${MOUNT_DIR} \
		--workdir ${MOUNT_DIR} \
		"${BUILDER_NAME}:${BUILDER_TAG}" ${1}
endef


%.image.exists:
	@docker inspect $* >/dev/null 2>&1 || \
		(echo "Image $* does not exist. Use 'make docker.builder' or 'make docker.base'." && false)

# TODO consider refactoring build targets so it builds each .o separately (perhaps cmake?)
ktrace_stats: ktrace_stats.c ktrace_shm.h stats.c stats.h ktrace_shm.c log.c log.h
	${CC} ${CFLAGS} -o $@ ktrace_stats.c ktrace_shm.c stats.c log.c -lrt -pthread -static

ktrace: ip_addr_hash.c ktrace.c ktrace_utils.c log.c dns_discovery.c ip_addr_hash.h ktrace.h ktrace_utils.h log.h ktrace_shm.h stats.c stats.h dns_discovery.h telemetry.h spd.h
	${CC} ${CLFAGS} -o $@ ip_addr_hash.c \
                              ktrace.c \
                              ktrace_utils.c \
                              log.c \
                              ktrace_shm.c \
                              stats.c \
                              dns_discovery.c \
                              telemetry.c \
                              spd.c \
                              -I/usr/local/include/dssl \
                              -I/usr/local/ssl/include \
                              -I/usr/include/glib-2.0 \
                              -L/usr/local/ssl/lib \
                              /usr/local/lib/libdssl.a \
                              -L/usr/local/lib \
                              -lpcap -lz -lssl -lcrypto -ldl \
                              -lrt -pthread -laudit -lauparse -lev -lglib-2.0 -lm\
                              -static
build: ktrace ktrace_stats

.PHONY: docker
docker: ${BASE_NAME}\:${BASE_TAG}.image.exists
	docker build \
		--build-arg BASE_IMAGE=${BASE_NAME}:${BASE_TAG} \
		--tag ${IMAGE_NAME}:${TAG} .
	docker tag ${IMAGE_NAME}:${TAG} ${DOCKER_REGISTRY}/${IMAGE_NAME}:${TAG}

.PHONY: docker.builder
docker.builder: opensource-submodule
	docker build -t ${BUILDER_NAME}:${BUILDER_TAG} builder/

.PHONY: docker.base
docker.base:
	docker build --no-cache\
		--tag ${BASE_NAME}:${BASE_TAG} base/

.PHONY: %_in_container
%_in_container: ${BUILDER_NAME}\:${BUILDER_TAG}.image.exists
	$(call run_in_container,make $*)

.PHONY: download_builder_image
download_builder_image:
	docker pull ${DOCKER_REGISTRY}/${BUILDER_NAME}:${BUILDER_TAG}
	docker tag ${DOCKER_REGISTRY}/${BUILDER_NAME}:${BUILDER_TAG} ${BUILDER_NAME}:${BUILDER_TAG}

.PHONY: download_base_image
download_base_image:
	docker pull ${DOCKER_REGISTRY}/${BASE_NAME}:${BASE_TAG}
	docker tag ${DOCKER_REGISTRY}/${BASE_NAME}:${BASE_TAG} ${BASE_NAME}:${BASE_TAG}

.PHONY: publish
publish:
	if gcloud container images describe ${DOCKER_REGISTRY}/${IMAGE_NAME}:${TAG} >/dev/null 2>/dev/null; \
	then \
		echo "Image with the commit tag ${TAG} already exists in the repository!"; \
	else \
		docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${TAG}; \
	fi

.PHONY: publish_base_image
publish_base_image:
	docker tag ${BASE_NAME}:${BASE_TAG} ${DOCKER_REGISTRY}/${BASE_NAME}:${BASE_TAG}
	docker push ${DOCKER_REGISTRY}/${BASE_NAME}:${BASE_TAG}

.PHONY: publish_builder_image
publish_builder_image:
	docker tag ${BUILDER_NAME}:${BUILDER_TAG} ${DOCKER_REGISTRY}/${BUILDER_NAME}:${BUILDER_TAG}
	docker push ${DOCKER_REGISTRY}/${BUILDER_NAME}:${BUILDER_TAG}

.PHONY: show-image-name
show-image-name:
	@echo ${DOCKER_REGISTRY}/${IMAGE_NAME}:${TAG}

.PHONY: opensource-submodule
opensource-submodule:
		echo "Updating OpenSource git submodule."; \
		git submodule update --init -- builder/OpenSource; \
		git submodule update --remote -- builder/OpenSource; \
