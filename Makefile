COMPOSE_DIR=./deployments
COMPOSE_FILE=$(COMPOSE_DIR)/docker-compose.yaml
ENV_FILE=.env
EXAMPLE_ENV_FILE=exampleenv

init_env:
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "Creating $(ENV_FILE) from $(EXAMPLE_ENV_FILE)..."; \
		cp $(EXAMPLE_ENV_FILE) $(ENV_FILE) \
	fi

up:
	echo "Starting service auth and ad with $(ENV_FILE)..."
	@docker compose -f $(COMPOSE_FILE) up -d

down:
	echo "Stopping service..."
	@docker compose -f $(COMPOSE_FILE) down

kill:
	echo "All data has deleted in database..."
	@docker compose -f $(COMPOSE_FILE) down -v

rebuild:
	echo "Rebuild service..."
	@docker compose -f $(COMPOSE_FILE) down
	@docker compose -f $(COMPOSE_FILE) up -d --build

.PHONY: init_env up down rebuild
