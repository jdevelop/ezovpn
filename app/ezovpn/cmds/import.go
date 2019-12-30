package cmds

import (
	"fmt"
	"io"
	"os"

	"github.com/jdevelop/ezovpn"
	"github.com/spf13/cobra"
)

var importFlags struct {
	InputFile string
}

var importCmd = &cobra.Command{
	Use:     "import",
	Aliases: []string{"imp"},
	Short:   "Imports an existing VPN configuration and embeds the certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			w io.Writer
			r io.Reader
		)
		if gConf.OutPath == "" {
			w = os.Stdout
		} else {
			ww, err := os.Create(gConf.OutPath)
			if err != nil {
				return fmt.Errorf("can't create output file for '%s': %w", gConf.OutPath, err)
			}
			defer ww.Close()
			w = ww
		}
		if importFlags.InputFile == "" {
			r = os.Stdin
		} else {
			rr, err := os.Open(importFlags.InputFile)
			if err != nil {
				return fmt.Errorf("can't open VPN config at '%s' : %w", importFlags.InputFile, err)
			}
			defer rr.Close()
			r = rr
		}
		return ezovpn.ImportVPNConfig(gConf.CertPath, r, w, ezovpn.DefaultCertFetcher)
	},
}
