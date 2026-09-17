.PHONY: test check install clean

test:
	python3 tests/e2e.py

check:
	@python3 -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('orchestrator', quiet=1) else 1)"
	@python3 -m py_compile bin/ctfctl tests/e2e.py tests/fake_service.py
	@for f in topology/*.sh bin/*.sh orchestrator/builder/*.sh install.sh; do bash -n "$$f" || exit 1; done
	@sh -n topology/guest/ctf-init && sh -n topology/guest/isolation-selftest.sh
	@echo "all sources parse"

install:
	sudo ./install.sh

clean:
	rm -rf orchestrator/__pycache__ tests/__pycache__ **/*.pyc
