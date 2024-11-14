
docker-build:
	$(MAKE) -C cc-dashboard-query-api docker-build

docker-push:
	$(MAKE) -C cc-dashboard-query-api docker-push

test:
	$(MAKE) -C cc-dashboard-query-api test

clean:
	$(MAKE) -C cc-dashboard-query-api clean
