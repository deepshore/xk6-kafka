package kafka

import (
	"context"
	"fmt"
	"maps"
	"math"
	"strconv"
	"strings"
	"time"

	ckafka "github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

// reservedSecurityConfigPrefixes lists connection- and security-critical
// librdkafka properties that the typed configuration owns exclusively. Raw
// passthrough config must never set or override these — even when the typed
// config leaves them unset — so a stray override cannot weaken TLS/SASL,
// re-enable an insecure transport, or redirect the broker list.
var reservedSecurityConfigPrefixes = []string{
	"bootstrap.servers",
	"security.protocol",
	"ssl.",
	"sasl.",
	"enable.ssl.certificate.verification",
}

func isReservedSecurityConfigKey(key string) bool {
	for _, prefix := range reservedSecurityConfigPrefixes {
		if key == prefix || strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// normalizeConfluentConfigValue coerces a value coming from JS/JSON into a type
// that confluent-kafka-go's value2string understands (bool, int, string). JSON
// decoding yields float64 for every number and sobek may yield int64, neither
// of which librdkafka accepts directly.
func normalizeConfluentConfigValue(value any) (any, error) {
	switch v := value.(type) {
	case bool, string, int:
		return v, nil
	case int64:
		return int(v), nil
	case int32:
		return int(v), nil
	case float64:
		if v == math.Trunc(v) {
			return int(v), nil
		}
		return nil, fmt.Errorf("%w: got non-integer number %v", errInvalidRawConfigValue, v)
	case float32:
		f := float64(v)
		if f == math.Trunc(f) {
			return int(f), nil
		}
		return nil, fmt.Errorf("%w: got non-integer number %v", errInvalidRawConfigValue, v)
	default:
		return nil, fmt.Errorf("%w: got %T", errInvalidRawConfigValue, value)
	}
}

// applyRawConfigOverrides merges user-supplied librdkafka properties into config.
// It is deliberately conservative:
//   - security/connection keys (reservedSecurityConfigPrefixes) are rejected, so
//     TLS, SASL, and the broker list cannot be tampered with.
//   - keys already set by the typed configuration are preserved, so existing
//     ("legacy") settings are never clobbered.
//
// Both categories are skipped with a warning rather than failing the run; only a
// malformed value (e.g. a non-integer number) aborts, since that signals a real
// mistake in the supplied config.
func applyRawConfigOverrides(config ckafka.ConfigMap, raw map[string]any) error {
	for key, rawValue := range raw {
		if isReservedSecurityConfigKey(key) {
			logger.Warnf(
				"Ignoring raw config key %q: security and connection settings cannot be overridden.",
				key,
			)
			continue
		}
		if _, exists := config[key]; exists {
			logger.Warnf(
				"Ignoring raw config key %q: it is already managed by xk6-kafka and will not be overwritten.",
				key,
			)
			continue
		}

		value, err := normalizeConfluentConfigValue(rawValue)
		if err != nil {
			return newInvalidConfigError(fmt.Sprintf("raw config key %q", key), err)
		}

		if err := setConfluentConfigValue(config, key, value); err != nil {
			return err
		}
	}

	return nil
}

const defaultConfluentTimeout = 5 * time.Second

const (
	confluentAutoOffsetResetEarliest = "earliest"
	confluentAutoOffsetResetLatest   = "latest"
)

func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

func cloneConfluentConfigMap(src ckafka.ConfigMap) ckafka.ConfigMap {
	dst := make(ckafka.ConfigMap, len(src))
	maps.Copy(dst, src)
	return dst
}

func newConfluentConfigMap(brokers []string) (ckafka.ConfigMap, error) {
	if len(brokers) == 0 {
		return nil, newInvalidConfigError("confluent config", errBrokersMustNotBeEmpty)
	}

	return ckafka.ConfigMap{
		"bootstrap.servers": strings.Join(brokers, ","),
	}, nil
}

func setConfluentConfigValue(config ckafka.ConfigMap, key string, value any) error {
	return config.SetKey(key, value)
}

func applyConfluentSecurityConfig(
	config ckafka.ConfigMap,
	saslConfig SASLConfig,
	tlsConfig TLSConfig,
) error {
	securityProtocol, err := confluentSecurityProtocol(saslConfig, tlsConfig)
	if err != nil {
		return err
	}
	if err := setConfluentConfigValue(config, "security.protocol", securityProtocol); err != nil {
		return err
	}

	if tlsConfig.EnableTLS {
		if tlsConfig.ServerCaPem != "" {
			if err := setConfluentConfigValue(config, "ssl.ca.pem", tlsConfig.ServerCaPem); err != nil {
				return err
			}
		}
		if tlsConfig.ClientCertPem != "" {
			if err := setConfluentConfigValue(config, "ssl.certificate.pem", tlsConfig.ClientCertPem); err != nil {
				return err
			}
		}
		if tlsConfig.ClientKeyPem != "" {
			if err := setConfluentConfigValue(config, "ssl.key.pem", tlsConfig.ClientKeyPem); err != nil {
				return err
			}
		}
		if tlsConfig.InsecureSkipTLSVerify {
			if err := setConfluentConfigValue(config, "enable.ssl.certificate.verification", false); err != nil {
				return err
			}
		}
	}

	if saslConfig.Algorithm == "" || saslConfig.Algorithm == none {
		return nil
	}

	mechanism, err := confluentSASLMechanism(saslConfig)
	if err != nil {
		return err
	}
	if err := setConfluentConfigValue(config, "sasl.mechanism", mechanism); err != nil {
		return err
	}

	switch saslConfig.Algorithm {
	case saslPlain, saslSsl, saslScramSha256, saslScramSha512:
		if err := setConfluentConfigValue(config, "sasl.username", saslConfig.Username); err != nil {
			return err
		}
		if err := setConfluentConfigValue(config, "sasl.password", saslConfig.Password); err != nil {
			return err
		}
	case saslAwsIam:
		return NewXk6KafkaError(
			unsupportedOperation,
			"AWS IAM SASL is not wired for the Confluent scaffold yet",
			nil,
		)
	}

	return nil
}

func confluentSecurityProtocol(saslConfig SASLConfig, tlsConfig TLSConfig) (string, error) {
	switch saslConfig.Algorithm {
	case "", none:
		if tlsConfig.EnableTLS {
			return "SSL", nil
		}
		return "PLAINTEXT", nil
	case saslSsl:
		if !tlsConfig.EnableTLS {
			return "", NewXk6KafkaError(
				failedCreateDialerWithSaslSSL,
				"You must enable TLS to use SASL_SSL",
				nil,
			)
		}
		return "SASL_SSL", nil
	case saslPlain, saslScramSha256, saslScramSha512, saslAwsIam, saslAzureEntra:
		if tlsConfig.EnableTLS {
			return "SASL_SSL", nil
		}
		return "SASL_PLAINTEXT", nil
	default:
		return "", NewXk6KafkaError(
			unsupportedOperation,
			"Unsupported SASL mechanism for Confluent scaffold",
			nil,
		)
	}
}

func confluentSASLMechanism(saslConfig SASLConfig) (string, error) {
	switch saslConfig.Algorithm {
	case saslPlain, saslSsl:
		return "PLAIN", nil
	case saslScramSha256:
		return "SCRAM-SHA-256", nil
	case saslScramSha512:
		return "SCRAM-SHA-512", nil
	case saslAwsIam:
		return "AWS_MSK_IAM", nil
	case saslAzureEntra:
		return "OAUTHBEARER", nil
	default:
		return "", NewXk6KafkaError(
			unsupportedOperation,
			"Unsupported SASL mechanism for Confluent scaffold",
			nil,
		)
	}
}

func writerConfigToConfluentConfigMap(writerConfig *WriterConfig) (ckafka.ConfigMap, error) {
	if writerConfig == nil {
		return nil, newMissingConfigError("writer config")
	}

	config, err := newConfluentConfigMap(writerConfig.Brokers)
	if err != nil {
		return nil, err
	}

	if err := applyConfluentSecurityConfig(config, writerConfig.SASL, writerConfig.TLS); err != nil {
		return nil, err
	}
	if err := setConfluentConfigValue(config, "go.delivery.reports", false); err != nil {
		return nil, err
	}
	if err := setConfluentConfigValue(config, "go.delivery.report.fields", "none"); err != nil {
		return nil, err
	}

	if writerConfig.BatchSize > 0 {
		if err := setConfluentConfigValue(config, "batch.num.messages", writerConfig.BatchSize); err != nil {
			return nil, err
		}
	}
	if writerConfig.BatchBytes > 0 {
		if err := setConfluentConfigValue(config, "batch.size", writerConfig.BatchBytes); err != nil {
			return nil, err
		}
	}
	if writerConfig.BatchTimeout > 0 {
		if err := setConfluentConfigValue(
			config,
			"linger.ms",
			int(writerConfig.BatchTimeout.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if writerConfig.WriteTimeout > 0 {
		if err := setConfluentConfigValue(
			config,
			"message.timeout.ms",
			int(writerConfig.WriteTimeout.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if writerConfig.ReadTimeout > 0 {
		if err := setConfluentConfigValue(
			config,
			"socket.timeout.ms",
			int(writerConfig.ReadTimeout.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if writerConfig.Compression != "" {
		if err := setConfluentConfigValue(config, "compression.type", writerConfig.Compression); err != nil {
			return nil, err
		}
	}
	acksValue, err := confluentRequiredAcks(writerConfig.RequiredAcks)
	if err != nil {
		return nil, err
	}
	if err := setConfluentConfigValue(config, "acks", acksValue); err != nil {
		return nil, err
	}

	if err := applyRawConfigOverrides(config, writerConfig.ProducerConfig); err != nil {
		return nil, err
	}

	return config, nil
}

func readerConfigToConfluentConfigMap(readerConfig *ReaderConfig) (ckafka.ConfigMap, error) {
	if readerConfig == nil {
		return nil, newMissingConfigError("reader config")
	}

	config, err := newConfluentConfigMap(readerConfig.Brokers)
	if err != nil {
		return nil, err
	}

	if err := applyConfluentSecurityConfig(config, readerConfig.SASL, readerConfig.TLS); err != nil {
		return nil, err
	}

	if readerConfig.MinBytes > 0 {
		if err := setConfluentConfigValue(config, "fetch.min.bytes", readerConfig.MinBytes); err != nil {
			return nil, err
		}
	}
	if readerConfig.MaxBytes > 0 {
		if err := setConfluentConfigValue(config, "fetch.max.bytes", readerConfig.MaxBytes); err != nil {
			return nil, err
		}
	}
	if readerConfig.MaxWait.Duration > 0 {
		if err := setConfluentConfigValue(
			config,
			"fetch.wait.max.ms",
			int(readerConfig.MaxWait.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if readerConfig.SessionTimeout > 0 {
		if err := setConfluentConfigValue(
			config,
			"session.timeout.ms",
			int(readerConfig.SessionTimeout.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if readerConfig.HeartbeatInterval > 0 {
		if err := setConfluentConfigValue(
			config,
			"heartbeat.interval.ms",
			int(readerConfig.HeartbeatInterval.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}
	if readerConfig.CommitInterval > 0 {
		if err := setConfluentConfigValue(
			config,
			"auto.commit.interval.ms",
			int(readerConfig.CommitInterval.Milliseconds()),
		); err != nil {
			return nil, err
		}
	}

	if readerConfig.GroupID != "" {
		if err := setConfluentConfigValue(config, "group.id", readerConfig.GroupID); err != nil {
			return nil, err
		}
		if err := setConfluentConfigValue(config, "enable.auto.commit", false); err != nil {
			return nil, err
		}

		autoOffsetReset := confluentAutoOffsetResetEarliest
		switch readerConfig.StartOffset {
		case "", firstOffset:
			autoOffsetReset = confluentAutoOffsetResetEarliest
		case lastOffset:
			autoOffsetReset = confluentAutoOffsetResetLatest
		default:
			if _, parseErr := strconv.ParseInt(readerConfig.StartOffset, 10, 64); parseErr == nil {
				autoOffsetReset = confluentAutoOffsetResetEarliest
			}
		}

		if err := setConfluentConfigValue(config, "auto.offset.reset", autoOffsetReset); err != nil {
			return nil, err
		}
	}

	if err := applyRawConfigOverrides(config, readerConfig.ConsumerConfig); err != nil {
		return nil, err
	}

	return config, nil
}

func connectionConfigToConfluentConfigMap(connectionConfig *ConnectionConfig) (ckafka.ConfigMap, error) {
	if connectionConfig == nil {
		return nil, newMissingConfigError("connection config")
	}
	brokers := append([]string(nil), connectionConfig.Brokers...)
	if len(brokers) == 0 {
		if connectionConfig.Address == "" {
			return nil, newInvalidConfigError("connection config", errAddressMustNotBeEmpty)
		}
		brokers = []string{connectionConfig.Address}
	}
	if len(brokers) == 0 {
		return nil, newInvalidConfigError("connection config", errAddressMustNotBeEmpty)
	}

	config, err := newConfluentConfigMap(brokers)
	if err != nil {
		return nil, err
	}

	if err := applyConfluentSecurityConfig(config, connectionConfig.SASL, connectionConfig.TLS); err != nil {
		return nil, err
	}

	if err := applyRawConfigOverrides(config, connectionConfig.ClientConfig); err != nil {
		return nil, err
	}

	return config, nil
}

func confluentRequiredAcks(requiredAcks int) (string, error) {
	switch requiredAcks {
	case -1:
		return "all", nil
	case 0:
		return "0", nil
	case 1:
		return "1", nil
	default:
		return "", newInvalidConfigError(
			"writer config",
			errRequiredAcksInvalid,
		)
	}
}

func confluentOffset(startOffset string, explicitOffset int64) (ckafka.Offset, error) {
	if explicitOffset > 0 {
		return ckafka.Offset(explicitOffset), nil
	}

	switch startOffset {
	case "", firstOffset:
		return ckafka.OffsetBeginning, nil
	case lastOffset:
		return ckafka.OffsetEnd, nil
	default:
		offset, err := strconv.ParseInt(startOffset, 10, 64)
		if err != nil {
			return ckafka.OffsetBeginning, newInvalidConfigError(
				"reader config",
				errStartOffsetInvalid,
			)
		}
		return ckafka.Offset(offset), nil
	}
}

func confluentPollTimeout(ctx context.Context) time.Duration {
	const maxPollStep = 100 * time.Millisecond
	ctx = ensureContext(ctx)

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		if remaining < maxPollStep {
			return remaining
		}
	}

	return maxPollStep
}

func confluentMetadataTimeoutMs(ctx context.Context) int {
	ctx = ensureContext(ctx)

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		return int(remaining.Milliseconds())
	}

	return int(defaultConfluentTimeout.Milliseconds())
}
