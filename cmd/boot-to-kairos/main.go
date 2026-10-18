//go:build linux

// Command boot-to-kairos replaces the running Linux system with Kairos.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/install"
	"github.com/lexfrei/boot-to-kairos/internal/mountns"
	"github.com/lexfrei/boot-to-kairos/internal/signature"
)

// version is stamped at release build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var o install.Options
	flag.StringVar(&o.Image, "image", "", "Kairos OCI image: a registry reference such as quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0, oci:DIR for an OCI image layout or oci-archive:FILE for one in a tar archive")
	flag.BoolVar(&o.InsecureRegistry, "insecure-registry", false, "allow plain http to a registry that is not at a loopback address; otherwise it is reached over https only")
	verify := flag.Bool("verify-signature", true, "refuse an image whose cosign signature does not verify; by default the signer must be Kairos's release pipeline")
	identity := flag.String("signature-identity", "", "regular expression the signing certificate's identity must match, to accept a signer other than Kairos; needs --signature-issuer")
	issuer := flag.String("signature-issuer", "", "OIDC issuer the signing certificate must name; needs --signature-identity")
	trustedRoot := flag.String("trusted-root", "", "Sigstore trusted_root.json to verify against, for a machine that cannot reach Sigstore's TUF repository")
	flag.StringVar(&o.Disk, "disk", "", "whole disk to replace, for example /dev/sda (all data is erased)")
	flag.StringVar(&o.ConfigPath, "cloud-config", "", "cloud-config for the installed system; optional while --keep-identity carries an admin login over")
	flag.BoolVar(&o.Yes, "yes", false, "do not ask for confirmation")
	flag.BoolVar(&o.KeepNetwork, "keep-network", true, "carry this system's addresses, routes, DNS, bonds, VLANs and bridges into the installed one, unless the cloud-config configures the network")
	flag.BoolVar(&o.KeepIdentity, "keep-identity", true, "carry this system's SSH users and their keys, SSH host keys and hostname into the installed one, where the cloud-config does not set them")
	flag.StringVar(&o.Output, "output", install.OutputText, "text, or json for one JSON object on stdout with the plan and the refusal, if any")
	flag.BoolVar(&o.DryRun, "dry-run", false, "check and build everything, then stop before the point of no return and print the plan; the disk is left alone")
	flag.StringVar(&o.WorkDir, "workdir", "", "existing directory on another disk to build the disk image in instead of RAM; only the unpacked image stays in a tmpfs")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	o.SkipSignature = !*verify
	if *identity != "" || *issuer != "" || *trustedRoot != "" {
		o.Signature = &install.SignatureOptions{Signer: signature.Policy{Identity: *identity, Issuer: *issuer}, TrustedRoot: *trustedRoot}
	}

	if *showVersion {
		fmt.Fprintln(os.Stdout, "boot-to-kairos", version)
		return
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "boot-to-kairos must run as root")
		os.Exit(1)
	}
	if !mountns.Inside() {
		os.Exit(reexec())
	}
	if err := mountns.Isolate(); err != nil {
		log.Fatal(err)
	}
	// A lost SSH session must cancel the build like Ctrl-C does, so that
	// the binds into the image are torn down.
	mountns.Absorb(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := install.Run(ctx, o); err != nil {
		log.Fatal(err)
	}
}

// reexec runs the installer again in a mount namespace of its own and waits
// for it. The child handles the signals; this process passes on the ones
// sent to it and must not die of them, and is locked in memory because it
// may still page in after the disk it was loaded from is overwritten.
// Handled, not ignored: an ignored signal would stay ignored in the child.
func reexec() int {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	_ = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	cmd := mountns.Command(context.Background(), "/proc/self/exe", os.Args[1:])
	cmd.Args[0] = os.Args[0]
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := mountns.Run(cmd, sigs)
	if _, ok := errors.AsType[*exec.ExitError](err); err != nil && !ok {
		fmt.Fprintln(os.Stderr, "boot-to-kairos:", err)
	}
	return mountns.ExitCode(err)
}
