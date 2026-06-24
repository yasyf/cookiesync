// Command cookiesync syncs your browser cookies across your Macs.
package main

import "github.com/yasyf/cookiesync/internal/cli"

var version = "dev"

func main() {
	cli.Execute(version)
}
