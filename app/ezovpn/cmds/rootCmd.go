package cmds

import (
	"github.com/spf13/cobra"
)

var (
	gConf struct {
		CertPath string
		OutPath  string
	}
	rootCmd = &cobra.Command{
		Hidden: true,
		Use:    "",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	gf := genCmd.PersistentFlags()
	gf.StringVarP(&genFlags.Host, "server", "s", "", "VPN Server")
	gf.IntVarP(&genFlags.Port, "port", "p", 1144, "VPN Port")
	gf.StringVar(&genFlags.Certs.CA, "ca", "ca.crt", "RSA CA file name")
	gf.StringVar(&genFlags.Certs.Cert, "cert", "", "RSA certificate file name")
	gf.StringVar(&genFlags.Certs.Key, "key", "", "RSA certificate key file name")
	gf.StringVar(&genFlags.Certs.TA, "ta", "ta.key", "VPN tls-auth key file name")

	for _, name := range []string{"cert", "key", "server"} {
		genCmd.MarkPersistentFlagRequired(name)
	}

	importCmd.PersistentFlags().StringVarP(&importFlags.InputFile, "import", "i", "", "VPN configuration file ( if not specified - stdin will be used )")

	rcf := rootCmd.PersistentFlags()
	rcf.StringVarP(&gConf.CertPath, "confdir", "d", "", "VPN root dir to look for certificates")
	rcf.StringVarP(&gConf.OutPath, "out", "o", "", ".ovpn config file ( if not specified - then stdout will be used )")

	rootCmd.MarkPersistentFlagRequired("confdir")
	rootCmd.AddCommand(genCmd)
	rootCmd.AddCommand(importCmd)
}
