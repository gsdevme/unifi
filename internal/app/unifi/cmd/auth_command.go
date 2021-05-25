package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"unifi/pkg/unifi/apiclient"
)

func NewAuthCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the Unifi API",
		Run: func(cmd *cobra.Command, args []string) {
			var (
				host     string
				username string
				password string
			)

			host = cmd.Flag("host").Value.String()
			username = cmd.Flag("username").Value.String()
			password = cmd.Flag("password").Value.String()

			c := apiclient.NewHttpClient(host, username, password)
			t, err := c.GetAuthToken()

			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())

				os.Exit(1)
			}

			print(t)
		},
	}

	command.Flags().String("host", "", "Unifi Host")
	command.Flags().String("username", "", "Unifi Username")
	command.Flags().String("password", "", "Unifi Password")
	_ = command.MarkFlagRequired("host")
	_ = command.MarkFlagRequired("username")
	_ = command.MarkFlagRequired("password")

	return command
}
