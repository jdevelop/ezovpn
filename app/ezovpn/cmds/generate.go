package cmds

import (
	"fmt"
	"io"
	"os"

	"github.com/jdevelop/ezovpn"
	"github.com/spf13/cobra"
)

var genFlags struct {
	Host  string
	Port  int
	Certs struct {
		CA   string
		Key  string
		Cert string
		TA   string
	}
}

var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"gen"},
	Short:   "Generates the config file according to the built-in template",
	RunE: func(cmd *cobra.Command, args []string) error {
		var w io.Writer
		if gConf.OutPath == "" {
			w = os.Stdout
		} else {
			ww, err := os.Create(gConf.OutPath)
			if err != nil {
				return fmt.Errorf("can't create output file for '%s': %w", gConf.OutPath, err)
			}
			w = ww
		}
		return ezovpn.GenerateVPNConfig(gConf.CertPath, &ezovpn.FileSpec{
			CAFile:   genFlags.Certs.CA,
			CertFile: genFlags.Certs.Cert,
			KeyFile:  genFlags.Certs.Key,
			TAFile:   genFlags.Certs.TA,
		}, &ezovpn.VpnSpec{
			Server: genFlags.Host,
			Port:   genFlags.Port,
		}, w, ezovpn.DefaultCertFetcher)
	},
}
