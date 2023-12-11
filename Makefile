build-toolchain:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml build

build-web-app:
	docker build --rm --cache-from sema-web-app:latest -t sema-web-app  -f SemaWebApp/Dockerfile .

build-scdg:
	# Setting network to host avoid eventual dns problems
	docker build --network=host  --rm --cache-from sema-scdg:latest -t sema-scdg -f SemaSCDG/Dockerfile .			   

run-web-app-service:
	docker run \
		--rm \
		-v $(PWD)/SemaWebApp/:/sema-web-app \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=$(DISPLAY) \
		-p 5000:5000 \
		--net=micro_network \
		--name="sema-web-app" \
		-it sema-web-app python3 application/SemaServer.py

run-scdg-service:	
	docker run \
		--rm \
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5001:5001 \
		--net=micro_network \
		--name="sema-scdg" \
		-it sema-scdg bash

run-scdg-test:	
	docker run \
		--rm -i\
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		--net=micro_network\
		--name="sema-scdg" \
		sema-scdg bash run_test.sh

run-toolchain-compose:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml up

# TODO better i think
run-toolchain-compose:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml up

run-toolchain:
	docker run \
		--rm -d -i\
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5001:5001 \
		--net=micro_network \
		--name="sema-scdg" \
		sema-scdg python3 SCDGApp.py
	sleep 5
	docker run \
		--rm \
		-v $(PWD)/SemaWebApp/:/sema-web-app \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=$(DISPLAY) \
		-p 5000:5000 \
		--net=micro_network \
		--name="sema-web-app"\
		-it sema-web-app python3 application/SemaServer.py

stop-all-containers:
	docker stop $$(docker ps -a -q)

ARGS = *
save-scdg-runs:
	sudo mv database/SCDG/runs/$(ARGS) database/SCDG/saved_runs/

clean-scdg-runs:
	sudo rm -r database/SCDG/runs/*

clean-scdg-saved-runs:
	sudo rm -r database/SCDG/saved_runs/*
				
clean-scdg-empty-directory:
	sudo rm -r -f SemaSCDG/application/submodules
	sudo rm -r -f SemaSCDG/application/penv-fix
	sudo rm -r -f SemaSCDG/application/database
	sudo rm -r -f SemaSCDG/application/logs

clean-docker:
	docker image prune
	docker image prune -a
	docker rmi $(docker images -a -q) 