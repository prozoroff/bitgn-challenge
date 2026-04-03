sync:
	uv sync

run:
	uv run python main.py $(ARGS)

# Single task: make task T=t01
task:
	uv run python main.py $(T)

.PHONY: sync run task
