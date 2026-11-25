.PHONY: campaign token api

campaign:
	./scripts/run-campaign.sh

token:
	./scripts/init-token.sh

api: token
	. ./.softhsm/env && cd kms-api && mvn -B -DskipTests package && java -jar target/kms-api.jar
