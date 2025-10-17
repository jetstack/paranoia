package options

import "github.com/spf13/cobra"

// Analyse are options for configuring certificate analysis.
type Analyse struct {
	// MozillaRemovedCertsURL is the URL to fetch the Mozilla removed CA certificates list from.
	MozillaRemovedCertsURL string `json:"mozilla_removed_certs_url"`
}

func RegisterAnalyse(cmd *cobra.Command) *Analyse {
	var opts Analyse
	cmd.PersistentFlags().StringVar(&opts.MozillaRemovedCertsURL, "mozilla-removed-certs-url", "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat", "URL to fetch Mozilla's removed CA certificate list from.")
	return &opts
}
