MODULES=competition_api tests
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# variables that control the volumes
HOST_CAPI_LOGS = $(ROOT_DIR)/capi_logs
export AUDIT_LOG = $(HOST_CAPI_LOGS)/audit.log

# variables the control the CP repos
HOST_CP_ROOT_DIR = $(ROOT_DIR)/cp_root

VOLUMES = $(HOST_CAPI_LOGS) $(HOST_CP_ROOT_DIR)

export WEB_CONCURRENCY=4

.PHONY: format sec lint build run test up down e2e loadtest

format:
	poetry run isort $(MODULES)
	poetry run black $(MODULES)
	prettier --write "./**/*.js"

sec:
	poetry run bandit $(MODULES)
	poetry run safety check $(MODULES)

lint:
	RC=0; \
	poetry run pylint $(MODULES) || RC=1; \
	poetry run black --check $(MODULES) || RC=1; \
	poetry run isort --check $(MODULES) || RC=1; \
	poetry run mypy $(MODULES) || RC=1; \
	exit $$RC

local-volumes:
	mkdir -p $(VOLUMES)

build:
	@docker build . -t capi

run: build
	docker run -it capi

test:
	poetry run pytest --cov=competition_api --cov-report term-missing:skip-covered ${TESTS}

compose-build:
	docker-compose build

compose-build-loadtest:
	docker-compose --profile loadtest build

up: local-volumes mock-cp compose-build
	docker-compose up

down:
	docker-compose down

down-volumes:
	docker-compose down -v

nginx-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare && make docker-pull

jenkins-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare && make docker-pull

mock-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare && make docker-pull

linux-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-001-linux-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare && make docker-pull

linux-harden-demo3: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone https://github.com/shellphish-support-syndicate/targets-semis-harden-demo3.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare && make docker-pull


clean-volumes:
	rm -rf $(VOLUMES)
	rm -f loadtest/loadtest_config.yaml

clean: down-volumes clean-volumes

e2e: clean clean-volumes local-volumes mock-cp compose-build
	:>$(AUDIT_LOG)
	WEB_CONCURRENCY=4 docker-compose up -d
	cd e2e && ./run.sh; docker-compose down
	cat $(AUDIT_LOG)

loadtest/loadtest_config.yaml:
	@printf -- "---\n" > $@
	@printf "auth:\n" >> $@
	@printf "  preload:\n" >> $@
	@for i in {1..100}; do printf "    %s: secret\n" $$(uuidgen) >> $@; done
	@printf "database:\n" >> $@
	@printf "  pool:\n" >> $@
	@printf "    size: 450\n" >> $@

loadtest: clean loadtest/loadtest_config.yaml mock-cp
	@docker compose --profile loadtest -f compose.yaml -f loadtest/compose_overrides.yaml up --force-recreate --exit-code-from loadtest --build
