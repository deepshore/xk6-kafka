export LOG_LEVEL=debug

build:
	GOOS=darwin GOARCH=arm64 xk6 build \
	--output dist/xk6-kafka_latest_darwin_arm64 \
	--with github.com/deepshore/xk6-kafka@add-tls-only=. \
	--with github.com/deepshore/kafka-go@v0.4.34=/Users/selamanse/Documents/GITHUB/kafka-go \
	--with github.com/deepshore/kafka-go/sasl/azure_entra@v0.1.7=/Users/selamanse/Documents/GITHUB/kafka-go/sasl/azure_entra \
	--with github.com/Dynatrace/xk6-output-dynatrace@latest 

build-linux:
	GOOS=linux GOARCH=amd64 xk6 build \
	--output dist/xk6-kafka_deepshoretesting_linux_amd64 \
	--with github.com/deepshore/xk6-kafka@add-tls-only=. \
	--with github.com/deepshore/kafka-go@v0.4.34=/Users/selamanse/Documents/GITHUB/kafka-go \
	--with github.com/deepshore/kafka-go/sasl/azure_entra@v0.1.7=/Users/selamanse/Documents/GITHUB/kafka-go/sasl/azure_entra \
	--with github.com/Dynatrace/xk6-output-dynatrace@latest 

build-remote:
	GOOS=darwin GOARCH=arm64 xk6 build \
	--output dist/xk6-kafka_latest_darwin_arm64 \
	--with github.com/deepshore/xk6-kafka@oauth-azure=.

test: build
	dist/xk6-kafka_latest_darwin_arm64 run scripts/test_tls_only.js

test-sasl: build
	dist/xk6-kafka_latest_darwin_arm64 run scripts/test_sasl_oauthbearer.js

convert-jks:
	openssl pkcs12 -in cert/truststore/kafka.truststore.jks -out fixtures/kafka.pemexport LOG_LEVEL=debug
