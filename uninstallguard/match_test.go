package main

import "testing"

func TestSplitCmd(t *testing.T) {
	for in, want := range map[string][2]string{
		`"C:\A B\unins000.exe" /x`:         {`C:\A B\unins000.exe`, "/x"},
		`MsiExec.exe /X{AAAA}`:             {"MsiExec.exe", "/X{AAAA}"},
		`C:\Program Files\App\un.exe -s`:   {`C:\Program Files\App\un.exe`, "-s"},
		`"C:\x\Update.exe" --uninstall -s`: {`C:\x\Update.exe`, "--uninstall -s"},
	} {
		if e, a := splitCmd(in); e != want[0] || a != want[1] {
			t.Errorf("%q → %q %q", in, e, a)
		}
	}
}

func TestMatches(t *testing.T) {
	g := `{12345678-ABCD-1234-ABCD-1234567890AB}`
	inno := Item{Name: "A", Key: `HKLM\x\A_is1`, Uninstall: `"C:\Program Files\A\unins000.exe"`, Dir: `C:\Program Files\A\`}
	msi := Item{Name: "B", Key: `HKLM\x\` + g, Uninstall: `MsiExec.exe /X` + g}
	sq := Item{Name: "C", Uninstall: `"C:\Users\u\AppData\Local\C\Update.exe" --uninstall -s`}
	yes := []struct {
		it       Item
		img, cmd string
	}{
		{inno, `C:\Program Files\A\unins000.exe`, `"C:\Program Files\A\unins000.exe"`},
		{inno, `C:\Users\u\AppData\Local\Temp\_iu14D2N.tmp`, `"C:\Users\u\AppData\Local\Temp\_iu14D2N.tmp" /SECONDPHASE="C:\Program Files\A\unins000.exe" /FIRSTPHASECWD="C:\Program Files\A\"`},
		{msi, `C:\Windows\System32\msiexec.exe`, `MsiExec.exe /X` + g},
		{msi, `C:\Windows\System32\msiexec.exe`, `msiexec /i ` + g + ` REMOVE=ALL`},
		{msi, `c:\windows\system32\MSIEXEC.EXE`, `msiexec.exe /uninstall ` + g + ` /qn`},
		{sq, `C:\Users\u\AppData\Local\C\Update.exe`, `"C:\Users\u\AppData\Local\C\Update.exe" --uninstall -s`},
	}
	for i, c := range yes {
		if !c.it.Matches(c.img, c.cmd) {
			t.Errorf("yes[%d] debería coincidir", i)
		}
	}
	no := []struct {
		it       Item
		img, cmd string
	}{
		{sq, `C:\Users\u\AppData\Local\C\Update.exe`, `"C:\Users\u\AppData\Local\C\Update.exe" --processStart C.exe`}, // el actualizador sigue funcionando
		{msi, `C:\Windows\System32\msiexec.exe`, `msiexec /V`},
		{msi, `C:\Windows\System32\msiexec.exe`, `msiexec /i ` + g},                                   // reparar/instalar no es desinstalar
		{msi, `C:\Windows\System32\msiexec.exe`, `msiexec /x {99999999-ABCD-1234-ABCD-1234567890AB}`}, // otro producto
		{inno, `C:\Program Files\A\A.exe`, `"C:\Program Files\A\A.exe"`},
		{inno, `C:\Program Files\B\unins000.exe`, `"C:\Program Files\B\unins000.exe"`},
	}
	for i, c := range no {
		if c.it.Matches(c.img, c.cmd) {
			t.Errorf("no[%d] no debería coincidir", i)
		}
	}
}
