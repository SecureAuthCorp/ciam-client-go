swagger = docker run --rm -it -e GOPATH=/go \
			-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
			-v $(shell pwd):/go/src \
			-w $(shell pwd)/src quay.io/goswagger/swagger:0.31

.PHONY: generate
generate: generate-acp generate-openbanking-uk generate-openbanking-brasil

SWAGGERS = public root developer oauth2 system admin web identity identityroot identitysystem identityself fdx obuk cdr ksa obbr opin hub licensingadmin licensingroot

generate-acp: $(SWAGGERS)

# swagger-MODULE
$(SWAGGERS):
	rm -rf clients/$@
	mkdir clients/$@

	sed -i "" "s|flow: application|flow: accessCode|g" spec/$@.yaml
	sed -i "" "s|flow: password|flow: accessCode|g" spec/$@.yaml
	${swagger} generate client -f /go/src/spec/$@.yaml -A acp -t /go/src/clients/$@ --struct-tags=yaml

.PHONY: generate-openbanking-uk
generate-openbanking-uk:
	rm -rf clients/openbankingUK
	mkdir -p clients/openbankingUK/accounts
	mkdir -p clients/openbankingUK/payments

	${swagger} generate client -f /go/src/spec/openbanking-uk-accounts-supported.yaml -A openbankingUKClient -t /go/src/clients/openbankingUK/accounts
	${swagger} generate client -f /go/src/spec/openbanking-uk-payments-supported.yaml -A openbankingUKClient -t /go/src/clients/openbankingUK/payments

.PHONY: generate-openbanking-brasil
generate-openbanking-brasil:
	rm -rf clients/openbankingBR
	mkdir -p clients/openbankingBR/consents
	mkdir -p clients/openbankingBR/payments

	${swagger} generate client -f /go/src/spec/openbanking-brasil-consents-supported.yaml -A openbankingBRClient -t /go/src/clients/openbankingBR/consents
	${swagger} generate client -f /go/src/spec/openbanking-brasil-payments-supported.yaml -A openbankingBRClient -t /go/src/clients/openbankingBR/payments
