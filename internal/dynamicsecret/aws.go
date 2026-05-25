//go:build dynamic_secrets

package dynamicsecret

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
)

// stsAssumeRoleAPI defines the interface for STS AssumeRole operations.
type stsAssumeRoleAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// AWSSTSEngine generates dynamic AWS STS credentials.
type AWSSTSEngine struct {
	defaultRoleARN string
	client         stsAssumeRoleAPI
}

// NewAWSSTSEngine creates a new AWS STS engine.
func NewAWSSTSEngine(roleARN string) *AWSSTSEngine {
	return &AWSSTSEngine{defaultRoleARN: roleARN}
}

// Type returns the engine type identifier.
func (e *AWSSTSEngine) Type() string {
	return EngineTypeAWSSTS
}

func (e *AWSSTSEngine) getClient(ctx context.Context) (stsAssumeRoleAPI, error) {
	if e.client != nil {
		return e.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-sts: load config: %w", err)
	}
	e.client = sts.NewFromConfig(cfg)
	return e.client, nil
}

// Generate calls STS AssumeRole and returns temporary credentials.
func (e *AWSSTSEngine) Generate(ctx context.Context, req GenerateRequest) (*Secret, error) {
	if err := e.Validate(ctx, req); err != nil {
		return nil, err
	}

	client, err := e.getClient(ctx)
	if err != nil {
		return nil, err
	}

	roleARN := req.Role
	if roleARN == "" {
		roleARN = e.defaultRoleARN
	}

	duration := int32(req.TTL.Seconds())
	if duration < 900 {
		duration = 900
	}
	if duration > 43200 {
		duration = 43200
	}

	sessionName := "symvault-session-" + uuid.New().String()[:8]

	output, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(duration),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-sts: assume role: %w", err)
	}

	if output.Credentials == nil {
		return nil, fmt.Errorf("aws-sts: empty credentials in response")
	}

	leaseID := uuid.New().String()

	leaseDuration := time.Duration(duration) * time.Second

	return &Secret{
		LeaseID:       leaseID,
		LeaseDuration: leaseDuration,
		Renewable:     false,
		CreatedAt:     time.Now().UTC(),
		EngineType:    EngineTypeAWSSTS,
		Data: map[string]any{
			"access_key_id":     aws.ToString(output.Credentials.AccessKeyId),
			"secret_access_key": aws.ToString(output.Credentials.SecretAccessKey),
			"session_token":     aws.ToString(output.Credentials.SessionToken),
			"expiration":        output.Credentials.Expiration.Format(time.RFC3339),
			"role_arn":          roleARN,
			"session_name":      sessionName,
		},
	}, nil
}

// Revoke is a no-op for AWS STS since credentials expire naturally.
func (e *AWSSTSEngine) Revoke(_ context.Context, _ string) error {
	return nil
}

// Validate checks that the request parameters are valid for AWS STS.
func (e *AWSSTSEngine) Validate(_ context.Context, req GenerateRequest) error {
	roleARN := req.Role
	if roleARN == "" {
		roleARN = e.defaultRoleARN
	}
	if roleARN == "" {
		return fmt.Errorf("aws-sts: role ARN is required")
	}
	if !strings.HasPrefix(roleARN, "arn:aws:iam::") && !strings.HasPrefix(roleARN, "arn:aws-us-gov:iam::") {
		return fmt.Errorf("aws-sts: invalid role ARN format: %q", roleARN)
	}
	if !strings.Contains(roleARN, ":role/") {
		return fmt.Errorf("aws-sts: role ARN must contain :role/: %q", roleARN)
	}
	return nil
}
