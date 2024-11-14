
docker-build:
	$(MAKE) -C cc-dashboard-query-api docker-build

test:
	$(MAKE) -C cc-dashboard-query-api test

clean:
	$(MAKE) -C cc-dashboard-query-api clean
