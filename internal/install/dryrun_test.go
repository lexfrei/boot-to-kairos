//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/efiboot"
	"github.com/lexfrei/boot-to-kairos/internal/flash"
	"github.com/lexfrei/boot-to-kairos/internal/identity"
	"github.com/lexfrei/boot-to-kairos/internal/netcfg"
	"github.com/lexfrei/boot-to-kairos/internal/quiesce"
)

// builtConfig is the cloud-config the last stubbed build got.
var builtConfig []byte

// stubMachine replaces every step from the network capture on with one that records
// its name, so that no test reaches the real disk, NVRAM or reboot.
func stubMachine(t *testing.T) *[]string {
	t.Helper()
	c, b, p, q, s, l, w, y, r := captureNetwork, buildImage, enterPointOfNoReturn, quiesceDisk, planStop, lockCheck, writeImage, syncOthers, reboot
	pe, ae, ci := prepareBootEntry, applyBootEntry, captureIdentity
	t.Cleanup(func() {
		captureNetwork, buildImage, enterPointOfNoReturn, quiesceDisk, planStop, lockCheck, writeImage, syncOthers, reboot = c, b, p, q, s, l, w, y, r
		prepareBootEntry, applyBootEntry, captureIdentity = pe, ae, ci
	})
	var calls []string
	captureIdentity = func(context.Context) (*identity.Host, error) {
		calls = append(calls, "capture identity")
		return &identity.Host{}, nil
	}
	captureNetwork = func() (*netcfg.Host, error) {
		calls = append(calls, "capture network")
		return &netcfg.Host{}, nil
	}
	buildImage = func(_ context.Context, _ Options, cfg []byte, plan *Plan) (string, error) {
		calls = append(calls, "build")
		builtConfig = cfg
		plan.Add("image.raw", "42 MiB used")
		return "/run/boot-to-kairos/image.raw", nil
	}
	prepareBootEntry = func(_, disk string, plan *Plan) (*efiboot.Plan, error) {
		calls = append(calls, "prepare boot entry")
		plan.addBootEntry(disk, nil, nil)
		return &efiboot.Plan{}, nil
	}
	applyBootEntry = func(*efiboot.Plan) { calls = append(calls, "write boot entry") }
	enterPointOfNoReturn = func() error {
		calls = append(calls, "point of no return")
		return nil
	}
	quiesceDisk = func(string) (func() error, error) {
		calls = append(calls, "quiesce")
		return func() error { return nil }, nil
	}
	planStop = func(string) (quiesce.Stop, error) {
		calls = append(calls, "plan stop")
		return quiesce.Stop{Swaps: []string{"/swap.img"}, Filesystems: []string{"/", "/boot/efi"}}, nil
	}
	lockCheck = func() error {
		calls = append(calls, "lock check")
		return nil
	}
	writeImage = func(string, string, int, flash.Progress) (flash.Stats, error) {
		calls = append(calls, "write")
		return flash.Stats{}, nil
	}
	syncOthers = func(string, time.Duration) { calls = append(calls, "sync") }
	reboot = func() error {
		calls = append(calls, "reboot")
		return nil
	}
	return &calls
}

func TestDryRunStopsBeforeThePointOfNoReturn(t *testing.T) {
	calls := stubMachine(t)
	plan := &Plan{}
	plan.Add("image", "quay.io/kairos/hadron:example")
	var out bytes.Buffer
	// Without --yes and with nothing to read, a prompt would abort.
	frozen := false
	err := proceed(context.Background(), Options{Disk: "/dev/vda", DryRun: true}, nil, plan, strings.NewReader(""), &out, &frozen)
	if err != nil || frozen {
		t.Fatalf("proceed = %v, past the point of no return %v; want nil and false: a dry run that would proceed succeeds", err, frozen)
	}
	if want := []string{"build", "prepare boot entry", "plan stop", "lock check"}; !slices.Equal(*calls, want) {
		t.Fatalf("calls = %v, want %v: nothing after the build may run", *calls, want)
	}
	if strings.Contains(out.String(), "Type the disk path") {
		t.Fatalf("dry run asked for confirmation:\n%s", out.String())
	}
	for _, re := range []string{
		`(?m)^  image: +quay.io/kairos/hadron:example$`,
		`(?m)^  image.raw: +42 MiB used$`,
		`(?m)^  boot entry: +"Kairos" for the image's EFI system partition; the entries for /dev/vda's partitions, if any, are removed$`,
		`(?m)^  swap to turn off: +/swap.img$`,
		`(?m)^  filesystems to stop: +/, /boot/efi$`,
	} {
		if !regexp.MustCompile(re).MatchString(out.String()) {
			t.Errorf("summary does not match %s:\n%s", re, out.String())
		}
	}
	if i, j := strings.Index(out.String(), "image:"), strings.Index(out.String(), "image.raw:"); i < 0 || j < i {
		t.Errorf("summary is not in the order the install computed it:\n%s", out.String())
	}
}

func TestDryRunReportsWhatWouldStopTheRealRun(t *testing.T) {
	calls := stubMachine(t)
	planStop = func(string) (quiesce.Stop, error) {
		*calls = append(*calls, "plan stop")
		return quiesce.Stop{}, quiesce.ErrUnplaceable
	}
	var out bytes.Buffer
	err := proceed(context.Background(), Options{Disk: "/dev/vda", DryRun: true}, nil, &Plan{}, strings.NewReader(""), &out, new(bool))
	if !errors.Is(err, quiesce.ErrUnplaceable) {
		t.Fatalf("proceed = %v, want the refusal the real run would hit", err)
	}
	if slices.Contains(*calls, "quiesce") || slices.Contains(*calls, "write") || slices.Contains(*calls, "reboot") {
		t.Fatalf("calls = %v: a refused dry run went on", *calls)
	}
}

func TestRealRunStillReachesTheReboot(t *testing.T) {
	calls := stubMachine(t)
	var out bytes.Buffer
	frozen := false
	if err := proceed(context.Background(), Options{Disk: "/dev/vda", Yes: true}, nil, &Plan{}, strings.NewReader(""), &out, &frozen); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	if !frozen {
		t.Error("the real run passed the point of no return without saying so: the work dir may be removed from a frozen filesystem")
	}
	if want := []string{"build", "prepare boot entry", "point of no return", "quiesce", "write", "sync", "write boot entry", "reboot"}; !slices.Equal(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
}

func TestRealRunAsksBeforeTheBuild(t *testing.T) {
	calls := stubMachine(t)
	var out bytes.Buffer
	err := proceed(context.Background(), Options{Disk: "/dev/vda"}, nil, &Plan{}, strings.NewReader("/dev/sdb\n"), &out, new(bool))
	if !errors.Is(err, ErrAborted) || len(*calls) != 0 {
		t.Fatalf("proceed = %v after %v, want ErrAborted before anything ran", err, *calls)
	}
}

func TestPlanSaysNoneForAnEmptyList(t *testing.T) {
	var out bytes.Buffer
	p := &Plan{}
	p.AddList("swap to turn off", nil)
	p.Print(&out)
	if !regexp.MustCompile(`(?m)^  swap to turn off: none$`).MatchString(out.String()) {
		t.Fatalf("summary = %q", out.String())
	}
}

func TestDryRunReportsAFailedLock(t *testing.T) {
	calls := stubMachine(t)
	lockCheck = func() error { return unix.ENOMEM }
	err := proceed(context.Background(), Options{Disk: "/dev/vda", DryRun: true}, nil, &Plan{}, strings.NewReader(""), io.Discard, new(bool))
	if !errors.Is(err, unix.ENOMEM) || slices.Contains(*calls, "quiesce") {
		t.Fatalf("proceed = %v after %v, want the mlockall failure the real run would hit", err, *calls)
	}
}

func TestPlanDescribesTheDiskAndTheImage(t *testing.T) {
	var out bytes.Buffer
	p := &Plan{}
	p.addDisk("/dev/vda", 20<<30, 4096)
	p.addRaw(3<<30+5<<20, 20<<30)
	p.Print(&out)
	want := "" +
		"  target disk: /dev/vda, 21474836480 bytes (20 GiB)\n" +
		"  sector size: 4096 bytes\n" +
		"  image.raw:   3077 MiB used of 20480 MiB\n"
	if out.String() != want {
		t.Fatalf("summary =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestPlanDescribesTheResolvedImage(t *testing.T) {
	var out bytes.Buffer
	p := &Plan{}
	p.addImage("OCI image archive", "sha256:f29481c2351b91ab61d28a40eb76a0a406120689f9fa93ac53f7f6f502159d89", []int64{144 << 20, 71<<20 + 1})
	p.Print(&out)
	want := "" +
		"  image source:   OCI image archive\n" +
		"  image manifest: sha256:f29481c2351b91ab61d28a40eb76a0a406120689f9fa93ac53f7f6f502159d89\n" +
		"  image layers:   2, 215 MiB as stored\n"
	if out.String() != want {
		t.Fatalf("summary =\n%s\nwant\n%s", out.String(), want)
	}
}

const plainConfig = "#cloud-config\nusers:\n  - name: kairos\n"

func staticHost() *netcfg.Host {
	mac := net.HardwareAddr{0x52, 0x54, 0, 0x12, 0x34, 0x56}
	return &netcfg.Host{
		Links: []netcfg.Link{{
			Index: 2, Name: "lan0", Type: 1, MAC: mac, PermMAC: mac, MTU: 1500,
			Addrs: []netcfg.Addr{{Prefix: netip.MustParsePrefix("192.0.2.10/24"), Global: true}},
		}},
		Routes: []netcfg.Route{{
			Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: netip.MustParseAddr("192.0.2.1"),
			Link: 2, Proto: 4, Type: 1, Table: 254,
		}},
	}
}

func TestDryRunPrintsTheCarriedNetwork(t *testing.T) {
	calls := stubMachine(t)
	captureNetwork = func() (*netcfg.Host, error) { return staticHost(), nil }
	var out bytes.Buffer
	o := Options{Disk: "/dev/vda", DryRun: true, KeepNetwork: true}
	if err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
		t.Fatalf("proceed = %v after %v", err, *calls)
	}
	if !strings.Contains(string(builtConfig), "192.0.2.10/24") {
		t.Errorf("the build got %q, without the carried network", builtConfig)
	}
	for _, re := range []string{
		`(?m)^  network files: +/etc/systemd/network/10-btk-525400123456.network$`,
		`(?m)^  network addresses: +lan0 192.0.2.10/24$`,
		`(?m)^  network routes: +lan0 default via 192.0.2.1$`,
	} {
		if !regexp.MustCompile(re).MatchString(out.String()) {
			t.Errorf("summary does not match %s:\n%s", re, out.String())
		}
	}
}

func TestDryRunRefusesWhatTheNetworkStepRefuses(t *testing.T) {
	daemon := staticHost()
	daemon.Routes[0].Proto = 12
	for name, capture := range map[string]func() (*netcfg.Host, error){
		"default route from a routing daemon": func() (*netcfg.Host, error) { return daemon, nil },
		"capture fails":                       func() (*netcfg.Host, error) { return nil, unix.EPERM },
	} {
		t.Run(name, func(t *testing.T) {
			calls := stubMachine(t)
			captureNetwork = capture
			o := Options{Disk: "/dev/vda", DryRun: true, KeepNetwork: true}
			err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), io.Discard, new(bool))
			if err == nil || !strings.Contains(err.Error(), "--keep-network=false") || len(*calls) != 0 {
				t.Fatalf("proceed = %v after %v, want the network refusal before anything ran", err, *calls)
			}
		})
	}
}

func TestDryRunSaysWhenTheNetworkIsNotCarried(t *testing.T) {
	for name, tc := range map[string]struct {
		keep bool
		want string
	}{
		"--keep-network=false":      {false, `(?m)^  network: +not carried \(--keep-network=false\)$`},
		"nothing but DHCP to carry": {true, `(?m)^  network: +not carried: nothing to carry over; Kairos brings its NICs up with DHCP$`},
	} {
		t.Run(name, func(t *testing.T) {
			calls := stubMachine(t)
			var out bytes.Buffer
			o := Options{Disk: "/dev/vda", DryRun: true, KeepNetwork: tc.keep}
			if err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
				t.Fatalf("proceed = %v", err)
			}
			if !regexp.MustCompile(tc.want).MatchString(out.String()) {
				t.Errorf("summary does not match %s:\n%s", tc.want, out.String())
			}
			if captured := slices.Contains(*calls, "capture network"); captured != tc.keep {
				t.Errorf("captured = %v with --keep-network=%v", captured, tc.keep)
			}
		})
	}
}

func TestRealRunCarriesTheNetworkBeforeItAsks(t *testing.T) {
	calls := stubMachine(t)
	o := Options{Disk: "/dev/vda", Yes: true, KeepNetwork: true}
	if err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), io.Discard, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	if want := []string{"capture network", "build", "prepare boot entry", "point of no return", "quiesce", "write", "sync", "write boot entry", "reboot"}; !slices.Equal(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}

	calls = stubMachine(t)
	captureNetwork = func() (*netcfg.Host, error) { return nil, unix.EPERM }
	var out bytes.Buffer
	o.Yes = false
	err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader("/dev/vda\n"), &out, new(bool))
	if !errors.Is(err, unix.EPERM) || len(*calls) != 0 || strings.Contains(out.String(), "Type the disk path") {
		t.Fatalf("proceed = %v after %v, prompt %q: a network refusal must stop the real run before it asks", err, *calls, out.String())
	}
}

func TestPlanDescribesTheBootEntry(t *testing.T) {
	for name, tc := range map[string]struct {
		avail, replace error
		want           string
	}{
		"written":             {nil, nil, `"Kairos" for the image's EFI system partition; the entries for /dev/vda's partitions, if any, are removed`},
		"old disk unreadable": {nil, unix.EIO, `"Kairos" for the image's EFI system partition; the old system's entries stay: input/output error`},
		"no efivarfs":         {unix.ENOENT, nil, `none (no such file or directory); the firmware has to fall back to \EFI\BOOT on the disk`},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			p := &Plan{}
			p.addBootEntry("/dev/vda", tc.avail, tc.replace)
			p.Print(&out)
			if want := "  boot entry: " + tc.want + "\n"; out.String() != want {
				t.Fatalf("summary = %q, want %q", out.String(), want)
			}
		})
	}
}

// On legacy BIOS the plan names the firmware mode and says there is no
// boot entry, in the text and in the JSON report.
func TestDryRunOnBIOS(t *testing.T) {
	for _, output := range []string{OutputText, OutputJSON} {
		calls := stubMachine(t)
		sys := fakeSys(t, false)
		prepareBootEntry = func(raw, disk string, plan *Plan) (*efiboot.Plan, error) {
			return bootEntry(sys, raw, disk, plan)
		}
		plan := &Plan{}
		var out bytes.Buffer
		o := Options{Disk: "/dev/vda", DryRun: true, Output: output}
		if err := proceed(context.Background(), o, nil, plan, strings.NewReader(""), &out, new(bool)); err != nil {
			t.Fatal(err)
		}
		if output == OutputJSON {
			report(&out, o, plan, nil, false)
		}
		want := []*regexp.Regexp{regexp.MustCompile(`firmware: +legacy BIOS\n`), regexp.MustCompile(`boot entry: +none; legacy BIOS boots`)}
		if output == OutputJSON {
			want = []*regexp.Regexp{regexp.MustCompile(`\{"name":"firmware","value":"legacy BIOS"\}`), regexp.MustCompile(`\{"name":"boot entry","value":"none; legacy BIOS boots`)}
		}
		for _, re := range want {
			if !re.MatchString(out.String()) {
				t.Errorf("%s output lacks %s:\n%s", output, re, out.String())
			}
		}
		if slices.Contains(*calls, "write boot entry") {
			t.Errorf("calls = %v", *calls)
		}
	}
}
