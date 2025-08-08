# Default target when just running `make`
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make up     # Deploys the AKS cluster and resources"
	@echo "  make down   # Destroys the AKS cluster and resources"
	@echo "  make clean  # Removes generated files"

# up target
.PHONY: up
up:
	@bash ./scripts/do_offical_deployment.sh --build

# down target
.PHONY: down
down: check
	@bash ./scripts/destroy.sh

# Clean up generated files (optional)
.PHONY: clean
clean:
	@rm -f ./tmp/ -r