package efiboot

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// efibootmgrKairos is what `efibootmgr --create --disk /dev/vda --part 15
// --label Kairos --loader '\EFI\BOOT\BOOTX64.EFI'` left in efivarfs on OVMF,
// after the four attribute bytes.
const efibootmgrKairos = "010000005e004b006100690072006f007300000004012a000f000000002800000000000000500300000000002ffa23f9fac21b409021b4594673bf6f0202040430005c004500460049005c0042004f004f0054005c0042004f004f0054005800360034002e0045004600490000007fff0400"

// Device paths of entries OVMF and Ubuntu leave behind, from efibootmgr -v.
const (
	ubuntuShim = "04012a000f000000002800000000000000500300000000002ffa23f9fac21b409021b4594673bf6f0202" +
		"04043400" + "5c00450046004900" + "5c007500620075006e0074007500" + "5c007300680069006d007800360034002e00650066006900" + "0000" + "7fff0400"
	ovmfMisc = "02010c00d041030a00000000" + "010106000003" + "7fff0400"
)

func option(t *testing.T, desc, path string) []byte {
	t.Helper()
	dp := mustHex(t, path)
	b := binary.LittleEndian.AppendUint32(nil, 1)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dp)))
	b = append(b, utf16z(desc)...)
	return append(b, dp...)
}

func TestLoadOptionMatchesEfibootmgr(t *testing.T) {
	got := loadOption("Kairos", ubuntuESP(t), `\EFI\BOOT\BOOTX64.EFI`)
	if want := mustHex(t, efibootmgrKairos); !bytes.Equal(got, want) {
		t.Fatalf("load option\n%x\nwant\n%x", got, want)
	}
}

func TestLoaderPath(t *testing.T) {
	for arch, want := range map[string]string{"amd64": `\EFI\BOOT\BOOTX64.EFI`, "arm64": `\EFI\BOOT\BOOTAA64.EFI`, "riscv64": `\EFI\BOOT\BOOTRISCV64.EFI`} {
		if got, err := loaderPath(arch); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", arch, got, err, want)
		}
	}
	if _, err := loaderPath("mips"); err == nil {
		t.Error("unknown arch accepted")
	}
}

func TestOldDiskMatches(t *testing.T) {
	esp := ubuntuESP(t).guid
	gpt := oldDisk{guids: [][16]byte{guidOf(t, "b3bc4f67c7772c43b33c2dfdca90dc45"), esp}}
	full := "02010c00d041030a00000000" + "010106000003" + ubuntuShim
	mbrHD := "04012a000100000000080000000000000000100000000000efbeadde000000000000000000000000" + "0101" + "7fff0400"
	cases := []struct {
		name string
		disk oldDisk
		opt  []byte
		want bool
	}{
		{"short HD path on the disk", gpt, option(t, "Ubuntu", ubuntuShim), true},
		{"full path with HD on the disk", gpt, option(t, "Ubuntu", full), true},
		{"device path without HD", gpt, option(t, "UEFI Misc Device", ovmfMisc), false},
		{"HD on another disk", oldDisk{guids: [][16]byte{guidOf(t, "00000000000000000000000000000001")}}, option(t, "Ubuntu", ubuntuShim), false},
		{"MBR HD on the disk", oldDisk{mbr: 0xdeadbeef}, option(t, "Debian", mbrHD), true},
		{"MBR HD on another disk", oldDisk{mbr: 0xdeadbeee}, option(t, "Debian", mbrHD), false},
		{"GPT HD against an MBR disk", oldDisk{mbr: 0xf923fa2f}, option(t, "Ubuntu", ubuntuShim), false},
		{"MBR HD with no signature against a GPT disk", gpt, option(t, "Debian", strings.Replace(mbrHD, "efbeadde", "00000000", 1)), false},
		{"HD node of the wrong length", gpt, option(t, "Ubuntu", "04010800ffffffff"+"7fff0400"), false},
		{"truncated path", gpt, option(t, "Ubuntu", ubuntuShim)[:20], false},
		{"node longer than the path", gpt, option(t, "Ubuntu", "04012a00"), false},
	}
	for _, c := range cases {
		if got := c.disk.matches(c.opt); got != c.want {
			t.Errorf("%s: matches %v, want %v", c.name, got, c.want)
		}
	}
}

// fakeVars stands in for efivarfs: names without the vendor GUID.
type fakeVars struct {
	vars    map[string][]byte
	failOn  map[string]error
	corrupt string
	writes  []string
	removes []string
}

func (f *fakeVars) names() ([]string, error) {
	n := []string{}
	for k := range f.vars {
		n = append(n, k)
	}
	return n, nil
}

func (f *fakeVars) read(name string) ([]byte, error) {
	b, ok := f.vars[name]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, syscall.ENOENT)
	}
	return bytes.Clone(b), nil
}

func (f *fakeVars) write(name string, data []byte) error {
	f.writes = append(f.writes, name)
	if err := f.failOn[name]; err != nil {
		return err
	}
	f.vars[name] = bytes.Clone(data)
	if name == f.corrupt {
		f.vars[name][0] ^= 1
	}
	return nil
}

func (f *fakeVars) remove(name string) error {
	f.removes = append(f.removes, name)
	if _, ok := f.vars[name]; !ok {
		return syscall.ENOENT
	}
	delete(f.vars, name)
	return nil
}

func order(nums ...uint16) []byte {
	b := []byte{}
	for _, n := range nums {
		b = binary.LittleEndian.AppendUint16(b, n)
	}
	return b
}

// ubuntuVM is the NVRAM of the e2e VM before the install, trimmed.
func ubuntuVM(t *testing.T) (*Plan, *fakeVars) {
	t.Helper()
	p := &Plan{
		option: mustHex(t, efibootmgrKairos),
		old:    oldDisk{guids: [][16]byte{ubuntuESP(t).guid}},
	}
	f := &fakeVars{vars: map[string][]byte{
		"Boot0000":  option(t, "BootManagerMenuApp", "0407140000"),
		"Boot0002":  option(t, "UEFI Misc Device", ovmfMisc),
		"Boot0009":  option(t, "Ubuntu", ubuntuShim),
		"BootOrder": order(9, 0, 2),
		"BootNext":  order(9),
	}, failOn: map[string]error{}}
	return p, f
}

func TestApplyFirstInstall(t *testing.T) {
	p, f := ubuntuVM(t)
	res, err := p.apply(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry != 1 || !res.Ordered || res.Position != 0 || !slices.Equal(res.Removed, []uint16{9}) {
		t.Fatalf("result %+v", res)
	}
	if !bytes.Equal(f.vars["Boot0001"], p.option) {
		t.Fatalf("Boot0001 = %x", f.vars["Boot0001"])
	}
	if !bytes.Equal(f.vars["BootOrder"], order(1, 0, 2)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
	for _, gone := range []string{"Boot0009", "BootNext"} {
		if _, ok := f.vars[gone]; ok {
			t.Errorf("%s kept", gone)
		}
	}
}

func TestApplyReusesItsEntry(t *testing.T) {
	p, f := ubuntuVM(t)
	f.vars["Boot0005"] = bytes.Clone(p.option)
	f.vars["BootOrder"] = order(9, 0, 5, 2)
	res, err := p.apply(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry != 5 || slices.Contains(f.writes, "Boot0001") {
		t.Fatalf("entry %04X, writes %v", res.Entry, f.writes)
	}
	if !bytes.Equal(f.vars["BootOrder"], order(5, 0, 2)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
}

func TestApplyAgainChangesNothing(t *testing.T) {
	p, f := ubuntuVM(t)
	if _, err := p.apply(f); err != nil {
		t.Fatal(err)
	}
	f.writes, f.removes = nil, nil
	if _, err := p.apply(f); err != nil {
		t.Fatal(err)
	}
	if len(f.writes)+len(f.removes) != 0 {
		t.Fatalf("second run wrote %v, removed %v", f.writes, f.removes)
	}
}

func TestApplyKeepsBootNextElsewhere(t *testing.T) {
	p, f := ubuntuVM(t)
	f.vars["BootNext"] = order(2)
	if _, err := p.apply(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.vars["BootNext"], order(2)) {
		t.Fatal("BootNext pointing at a live entry was dropped")
	}
}

func TestApplyNoBootOrder(t *testing.T) {
	p, f := ubuntuVM(t)
	delete(f.vars, "BootOrder")
	if _, err := p.apply(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.vars["BootOrder"], order(1)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
}

// A full NVRAM gets room from the entries that point at the replaced disk.
func TestApplyFullNVRAM(t *testing.T) {
	p, f := ubuntuVM(t)
	retried := &retryOnce{fakeVars: f, name: "Boot0001"}
	res, err := p.apply(retried)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry != 1 || !bytes.Equal(f.vars["BootOrder"], order(1, 0, 2)) {
		t.Fatalf("result %+v, BootOrder %x", res, f.vars["BootOrder"])
	}
	if retried.tries != 2 || retried.removedBeforeRetry != 1 || f.removes[0] != "Boot0009" {
		t.Fatalf("tries %d, removes %v, removed before retry %d", retried.tries, f.removes, retried.removedBeforeRetry)
	}
}

// retryOnce fails the first write of name with ENOSPC and counts what was
// removed before the second.
type retryOnce struct {
	*fakeVars

	name               string
	tries              int
	removedBeforeRetry int
}

func (r *retryOnce) write(name string, data []byte) error {
	if name == r.name {
		r.tries++
		if r.tries == 1 {
			r.writes = append(r.writes, name)
			return syscall.ENOSPC
		}
		r.removedBeforeRetry = len(r.removes)
	}
	return r.fakeVars.write(name, data)
}

func TestApplyEntryFailsStillCleansUp(t *testing.T) {
	p, f := ubuntuVM(t)
	f.failOn["Boot0001"] = syscall.EIO
	res, err := p.apply(f)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error %v, want EIO", err)
	}
	if tries := len(slices.DeleteFunc(slices.Clone(f.writes), func(n string) bool { return n != "Boot0001" })); tries != 1 {
		t.Fatalf("Boot0001 written %d times; only a full NVRAM is worth a retry", tries)
	}
	if res.Entry != noEntry || res.Ordered {
		t.Fatalf("result %+v; no entry was written", res)
	}
	if !bytes.Equal(f.vars["BootOrder"], order(0, 2)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
	if _, ok := f.vars["Boot0009"]; ok {
		t.Fatal("stale entry kept")
	}
}

func TestApplyNoSpaceEvenAfterCleanup(t *testing.T) {
	p, f := ubuntuVM(t)
	f.failOn["Boot0001"] = syscall.ENOSPC
	res, err := p.apply(f)
	if !errors.Is(err, syscall.ENOSPC) || res.Entry != noEntry {
		t.Fatalf("entry %04X, error %v", res.Entry, err)
	}
	if !bytes.Equal(f.vars["BootOrder"], order(0, 2)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
}

func TestApplyReadBackMismatch(t *testing.T) {
	p, f := ubuntuVM(t)
	f.corrupt = "Boot0001"
	res, err := p.apply(f)
	if !errors.Is(err, ErrReadBack) || res.Entry != noEntry {
		t.Fatalf("entry %04X, error %v", res.Entry, err)
	}
	if bytes.Contains(f.vars["BootOrder"], order(1)) {
		t.Fatalf("BootOrder %x names an entry that did not verify", f.vars["BootOrder"])
	}
	if _, ok := f.vars["Boot0001"]; ok {
		t.Fatal("the entry that did not verify was left behind")
	}
}

func TestApplyBootOrderFails(t *testing.T) {
	p, f := ubuntuVM(t)
	f.failOn["BootOrder"] = syscall.EIO
	res, err := p.apply(f)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error %v, want EIO", err)
	}
	if res.Entry != 1 || res.Ordered {
		t.Fatalf("result %+v; the entry is not in BootOrder", res)
	}
	if _, ok := f.vars["Boot0009"]; ok {
		t.Fatal("stale entry kept after a BootOrder failure")
	}
}

func TestApplyPicksLowestFreeNumber(t *testing.T) {
	p, f := ubuntuVM(t)
	f.vars["Boot0001"] = option(t, "Other", ovmfMisc)
	f.vars["Boot000A"] = option(t, "Other", ovmfMisc)
	f.vars["BootOrder"] = order(9, 0, 1, 2, 10)
	res, err := p.apply(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry != 3 || !bytes.Equal(f.vars["BootOrder"], order(3, 0, 1, 2, 10)) {
		t.Fatalf("entry %04X, BootOrder %x", res.Entry, f.vars["BootOrder"])
	}
}

func TestBootNumber(t *testing.T) {
	for name, want := range map[string]int{"Boot0000": 0, "Boot00AF": 0xaf, "BootFFFF": 0xffff, "Boot00af": -1, "BootOrder": -1, "Boot00001": -1, "BootNext": -1} {
		if got := bootNumber(name); got != want {
			t.Errorf("%s: %d, want %d", name, got, want)
		}
	}
}

// efivarfs deletes a variable written with no data, so an empty BootOrder
// is removed, not written.
func TestApplyEmptiesBootOrder(t *testing.T) {
	p, f := ubuntuVM(t)
	f.failOn["Boot0001"] = syscall.EIO
	f.vars["BootOrder"] = order(9)
	_, err := p.apply(f)
	if !errors.Is(err, syscall.EIO) || strings.Contains(err.Error(), "BootOrder") {
		t.Fatalf("error %v, want only the entry's", err)
	}
	if b, ok := f.vars["BootOrder"]; ok {
		t.Fatalf("BootOrder %x kept", b)
	}
}

func TestResultString(t *testing.T) {
	for _, c := range []struct {
		r    Result
		want string
	}{
		{Result{Entry: 0xa, Ordered: true, Removed: []uint16{9}}, `Boot000A "Kairos" first in BootOrder, removed Boot0009`},
		{Result{Entry: 0xa, Ordered: true, Position: 2}, `Boot000A "Kairos" at position 3 in BootOrder`},
		{Result{Entry: 0xa}, `Boot000A "Kairos" written, not in BootOrder`},
		{Result{Entry: noEntry, Removed: []uint16{9, 0x10}}, `no boot entry, removed Boot0009, removed Boot0010`},
	} {
		if got := c.r.String(); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// On a fleet that boots from the network first, the entry takes the old
// system's place behind the network entry instead of jumping ahead of it.
func TestApplyTakesTheOldSystemsPlace(t *testing.T) {
	cases := []struct {
		name  string
		setup func(p *Plan, f *fakeVars)
		want  []byte
		pos   int
	}{
		{"behind PXE", func(_ *Plan, f *fakeVars) {
			f.vars["BootOrder"] = order(4, 9, 0, 2)
		}, order(4, 1, 0, 2), 1},
		{"first of several stale", func(_ *Plan, f *fakeVars) {
			f.vars["Boot0007"] = option(t, "Ubuntu old", ubuntuShim)
			f.vars["BootOrder"] = order(4, 9, 0, 7, 2)
		}, order(4, 1, 0, 2), 1},
		{"no stale entry", func(_ *Plan, f *fakeVars) {
			delete(f.vars, "Boot0009")
			f.vars["BootOrder"] = order(4, 0, 2)
		}, order(1, 4, 0, 2), 0},
		{"stale entry not in BootOrder", func(_ *Plan, f *fakeVars) {
			f.vars["BootOrder"] = order(4, 0, 2)
		}, order(1, 4, 0, 2), 0},
		{"reused entry keeps its place", func(p *Plan, f *fakeVars) {
			delete(f.vars, "Boot0009")
			f.vars["Boot0005"] = bytes.Clone(p.option)
			f.vars["BootOrder"] = order(4, 5, 0, 2)
		}, order(4, 5, 0, 2), 1},
	}
	for _, c := range cases {
		p, f := ubuntuVM(t)
		f.vars["Boot0004"] = option(t, "UEFI PXEv4", ovmfMisc)
		c.setup(p, f)
		res, err := p.apply(f)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bytes.Equal(f.vars["BootOrder"], c.want) || !res.Ordered || res.Position != c.pos {
			t.Errorf("%s: BootOrder %x, %+v; want %x at position %d", c.name, f.vars["BootOrder"], res, c.want, c.pos)
		}
	}
}

func TestApplyNoEntryBehindPXE(t *testing.T) {
	p, f := ubuntuVM(t)
	f.vars["Boot0004"] = option(t, "UEFI PXEv4", ovmfMisc)
	f.vars["BootOrder"] = order(4, 9, 0, 2)
	f.failOn["Boot0001"] = syscall.EIO
	if _, err := p.apply(f); !errors.Is(err, syscall.EIO) {
		t.Fatalf("error %v, want EIO", err)
	}
	if !bytes.Equal(f.vars["BootOrder"], order(4, 0, 2)) {
		t.Fatalf("BootOrder %x", f.vars["BootOrder"])
	}
}
