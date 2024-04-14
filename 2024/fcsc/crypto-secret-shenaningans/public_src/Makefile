ifeq ($(FORCE_REBUILD),1)
RECREATE=--force-recreate
else
RECREATE=
endif

ifeq ($(VERBOSE),1)
BUILDKIT_PROGRESS=plain
endif


all:
	DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=$(BUILDKIT_PROGRESS) docker compose up --build $(RECREATE)
