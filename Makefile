SET ?= l06_security
PROFILE ?= lesson-06

.PHONY: eval dry-run

eval:
	docker compose run --rm eval --set $(SET) --profile $(PROFILE)

dry-run:
	docker compose run --rm eval --set $(SET) --dry-run
