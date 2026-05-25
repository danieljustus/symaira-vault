package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/dynamicsecret"
	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

var (
	dynamicEngine string
	dynamicRole   string
	dynamicTTL    time.Duration
)

var dynamicCmd = &cobra.Command{
	Use:   "dynamic",
	Short: "Generate dynamic secrets with time-limited leases",
	Long: `Generate dynamic secrets with time-limited leases for various backends.

Supported engines:
  postgres  - Create temporary PostgreSQL users with GRANT role
  aws-sts   - Generate temporary AWS STS credentials via AssumeRole`,
	Example: `  # Generate temporary PostgreSQL credentials valid for 1h
  symvault dynamic generate postgres --role analyst --ttl 1h

  # Short-lived AWS STS session
  symvault dynamic generate aws-sts --role arn:aws:iam::123:role/dev --ttl 15m`,
}

var dynamicGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a dynamic secret",
	Example: `  # Generate a PostgreSQL secret with readonly role
  symvault dynamic generate --engine postgres --role readonly --ttl 1h

  # Generate AWS STS credentials for a specific role
  symvault dynamic generate --engine aws-sts --role arn:aws:iam::123456789012:role/MyRole --ttl 30m`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(svc vaultsvc.Service) error {
			ctx := context.Background()
			mgr := dynamicsecret.NewManager(svc)

			req := dynamicsecret.GenerateRequest{
				Role: dynamicRole,
				TTL:  dynamicTTL,
			}

			secret, err := mgr.Generate(ctx, dynamicEngine, req)
			if err != nil {
				return fmt.Errorf("generate dynamic secret: %w", err)
			}

			result := map[string]any{
				"lease_id":    secret.LeaseID,
				"engine_type": secret.EngineType,
				"expires_in":  secret.LeaseDuration.String(),
				"created_at":  secret.CreatedAt.Format(time.RFC3339),
				"data":        secret.Data,
			}

			return PrintResult(result)
		})
	},
}

func init() {
	dynamicGenerateCmd.Flags().StringVar(&dynamicEngine, "engine", "", "Secret engine type (postgres, aws-sts)")
	dynamicGenerateCmd.Flags().StringVar(&dynamicRole, "role", "", "Role or permission level")
	dynamicGenerateCmd.Flags().DurationVar(&dynamicTTL, "ttl", time.Hour, "Time-to-live duration (e.g., 1h, 30m)")
	_ = dynamicGenerateCmd.MarkFlagRequired("engine")
	_ = dynamicGenerateCmd.MarkFlagRequired("role")

	dynamicCmd.AddCommand(dynamicGenerateCmd)
	rootCmd.AddCommand(dynamicCmd)
}
