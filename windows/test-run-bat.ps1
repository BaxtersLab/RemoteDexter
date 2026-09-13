<#
    Run windows\run.bat and inspect what the host process ACTUALLY receives.

    WHY THIS EXISTS

    On 2026-09-05 the Linux packaged launcher was found granting no
    capabilities at all: install the .deb, click the icon, and the host could
    not capture the screen. It survived every gate because the test for that
    class read a file's TEXT, and it was reading the wrong file at that.

    Both halves were fixed on Linux. The first fix pointed the text test at the
    packaged launcher; the second (scripts/test-packaged-launcher.sh) EXECUTES
    that launcher in a mount namespace and asserts on the environment the host
    receives. Windows got the first half only. run.bat's properties are still
    proven by reading it, and `set RD_CAP_SCREENSHOT=1` can sit on a line that
    never runs -- after an `exit /b`, inside an untaken `if`, or below the
    `start` that already launched the exe. The grep is satisfied and the
    operator still gets a blank phone.

    So this runs it.

    HOW THE STUB GETS THERE. run.bat launches "%~dp0host_app.exe" -- the file
    NEXT TO ITSELF. That is the correct design (the portable package is
    unpacked wherever the operator likes) and it means no PATH trick and no
    environment override is needed: a byte-identical copy of run.bat in a
    scratch directory, with a stub host_app.exe beside it, is the same program
    running the way it ships. The copy is verified by SHA256 against the
    shipping file before every positive assertion. Only the negative controls
    are mutated, and those are separate copies.

    WHAT ONLY A REAL cmd.exe CAN PROVE, and the reason this cannot be a Rust
    test: that `set RD_CAP_INPUT=1 && run.bat` -- the obvious form -- gives the
    host "1 " with a trailing space, while `set "RD_CAP_INPUT=1" && run.bat`
    gives it "1". The host side is already pinned in Rust
    (host_app::tests::the_gate_is_still_exact_and_was_not_loosened proves "1 "
    does NOT grant). The cmd side has only ever been a comment in run.bat.
    Together they are the whole defect: the operator does what they were told
    and control stays off.

    THIS SCRIPT HAS NEVER BEEN RUN ON LINUX AND CANNOT BE. It ships UNVERIFIED.
    Its negative controls run on every invocation precisely so that the first
    Windows round to execute it proves the harness as well as the launcher.

    Usage:  powershell -ExecutionPolicy Bypass -File windows\test-run-bat.ps1
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Launcher = Join-Path $PSScriptRoot 'run.bat'
$Console  = Join-Path $PSScriptRoot 'run-console.bat'
$script:Pass = 0
$script:Fail = 0

function Ok  ([string]$m) { $script:Pass++; Write-Host ("  ok    " + $m) }
function Bad ([string]$m) { $script:Fail++; Write-Host ("  FAIL  " + $m) -ForegroundColor Red }
function Check ([bool]$cond, [string]$m) { if ($cond) { Ok $m } else { Bad $m } }

if (-not (Test-Path $Launcher)) { Write-Error "no launcher at $Launcher"; exit 2 }

$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("rd-runbat-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work -Force | Out-Null

try {
    # ---- the stub -----------------------------------------------------------
    # A real PE is required: cmd's `start` will not execute a batch file named
    # .exe. Built with the csc that ships with the .NET Framework, so this needs
    # no SDK and no network.
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path $csc)) {
        $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    if (-not (Test-Path $csc)) {
        Write-Host "no csc.exe found; cannot build the stub host_app.exe" -ForegroundColor Red
        Write-Host "REFUSING to report a pass for a launcher that was never run" -ForegroundColor Red
        exit 2
    }

    $stubSrc = Join-Path $Work 'stub.cs'
    $stubExe = Join-Path $Work 'host_app.exe'
@'
using System;
using System.Collections;
using System.IO;
using System.Text;

// Stands in for host_app.exe and records exactly what it was handed.
// Not a mock of the host: it is the exec target, so the LAUNCHER's behaviour
// can be observed. Nothing ships it.
class Stub {
    static int Main(string[] args) {
        string outPath = Environment.GetEnvironmentVariable("RD_STUB_OUT");
        if (string.IsNullOrEmpty(outPath)) return 2;
        StringBuilder sb = new StringBuilder();
        sb.Append("EXE\t").Append(System.Reflection.Assembly.GetExecutingAssembly().Location).Append("\n");
        sb.Append("ARGC\t").Append(args.Length).Append("\n");
        foreach (string a in args) sb.Append("ARGV\t").Append(a).Append("\n");
        foreach (DictionaryEntry e in Environment.GetEnvironmentVariables()) {
            sb.Append("ENV\t").Append(e.Key).Append("\t").Append(e.Value).Append("\n");
        }
        File.WriteAllText(outPath, sb.ToString());
        return 0;
    }
}
'@ | Set-Content -Path $stubSrc -Encoding UTF8

    & $csc /nologo /target:exe /out:$stubExe $stubSrc | Out-Null
    if (-not (Test-Path $stubExe)) {
        Write-Host "the stub host_app.exe did not build" -ForegroundColor Red
        exit 2
    }
    Write-Host "  stub: built with $csc"

    $LauncherHash = (Get-FileHash -Algorithm SHA256 $Launcher).Hash

    # ---- the runner ---------------------------------------------------------
    # Returns a hashtable: Env (name->value), Exe, Argv, Ran, Rc, Out.
    function Invoke-Launcher {
        param(
            [string]$Tag,
            [string]$LauncherFile = $Launcher,
            [string]$Pre = '',          # a literal cmd prefix, e.g. 'set "RD_CAP_INPUT=1" &&'
            [switch]$NoExe,             # do not place host_app.exe next to it
            [switch]$Mutant             # skip the byte-identity assertion
        )
        $box = Join-Path $Work $Tag
        New-Item -ItemType Directory -Path $box -Force | Out-Null
        $bat = Join-Path $box 'run.bat'
        Copy-Item $LauncherFile $bat -Force

        if (-not $Mutant) {
            $h = (Get-FileHash -Algorithm SHA256 $bat).Hash
            if ($h -ne $LauncherHash) {
                Bad "the copy under test is not byte-identical to windows\run.bat"
            }
        }
        if (-not $NoExe) { Copy-Item $stubExe (Join-Path $box 'host_app.exe') -Force }

        $outFile = Join-Path $box 'stub.out'
        $env:RD_STUB_OUT = $outFile

        # `pause` in the missing-exe branch reads stdin, so an unattended run
        # MUST redirect it or the script hangs forever waiting for a keypress.
        $cmdline = if ($Pre -ne '') { "$Pre `"$bat`" < NUL" } else { "`"$bat`" < NUL" }
        $stdout = & cmd.exe /c $cmdline 2>&1
        $rc = $LASTEXITCODE

        # `start` is asynchronous: the launcher returns before the exe has run.
        $deadline = (Get-Date).AddSeconds(20)
        while ((-not (Test-Path $outFile)) -and ((Get-Date) -lt $deadline)) {
            Start-Sleep -Milliseconds 200
        }

        $envMap = @{}; $exe = ''; $argv = @(); $ran = $false
        if (Test-Path $outFile) {
            $ran = $true
            foreach ($line in (Get-Content $outFile)) {
                $p = $line -split "`t", 3
                if ($p[0] -eq 'ENV' -and $p.Count -ge 3) { $envMap[$p[1]] = $p[2] }
                elseif ($p[0] -eq 'EXE'  -and $p.Count -ge 2) { $exe = $p[1] }
                elseif ($p[0] -eq 'ARGV' -and $p.Count -ge 2) { $argv += $p[1] }
            }
        }
        Remove-Item Env:\RD_STUB_OUT -ErrorAction SilentlyContinue
        return @{ Env = $envMap; Exe = $exe; Argv = $argv; Ran = $ran; Rc = $rc; Out = ($stdout -join "`n"); Box = $box }
    }

    function EnvOf ([hashtable]$r, [string]$name) {
        if ($r.Env.ContainsKey($name)) { return $r.Env[$name] } else { return $null }
    }

    # Make sure nothing inherited from the caller can fake a pass.
    foreach ($v in 'RD_CAP_SCREENSHOT','RD_CAP_INPUT','RD_CAP_CLIPBOARD') {
        Remove-Item ("Env:\" + $v) -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host '  -- the launcher that ships, run unmodified --'

    # 1. the grant the product cannot work without
    $r = Invoke-Launcher -Tag 'grant'
    Check ($r.Ran) "it actually starts the host: the stub ran"
    $s = EnvOf $r 'RD_CAP_SCREENSHOT'
    Check ($s -eq '1') ("the host RECEIVES RD_CAP_SCREENSHOT=1 (got '" + $s + "')")
    Check ($s -ne $null -and $s.Length -eq 1) 'the value is exactly "1", not "1 " or "true"'
    Check ($r.Rc -eq 0) ("the launcher exits 0 (got " + $r.Rc + ")")

    # 2. what it must NOT grant
    Check ((EnvOf $r 'RD_CAP_INPUT') -eq $null)     'control is NOT granted: RD_CAP_INPUT unset'
    Check ((EnvOf $r 'RD_CAP_CLIPBOARD') -eq $null) 'clipboard is NOT granted: RD_CAP_CLIPBOARD unset'

    # 3. it launches the exe BESIDE IT, not one found on PATH
    $expectedExe = Join-Path $r.Box 'host_app.exe'
    Check ($r.Exe -eq $expectedExe) ("it runs the exe next to the .bat, not one on PATH (ran '" + $r.Exe + "')")

    # 4. THE DOCUMENTED INSTRUCTION, EXECUTED. This is the pair that only a real
    #    cmd.exe can settle.
    Write-Host ''
    Write-Host '  -- the quoted form works, the obvious form does not --'
    $q = Invoke-Launcher -Tag 'quoted' -Pre 'set "RD_CAP_INPUT=1" &&'
    $qi = EnvOf $q 'RD_CAP_INPUT'
    Check ($qi -eq '1') ("the DOCUMENTED `set `"RD_CAP_INPUT=1`"` reaches the host as exactly '1' (got '" + $qi + "')")
    Check ((EnvOf $q 'RD_CAP_SCREENSHOT') -eq '1') 'and viewing survives alongside it'
    Check ((EnvOf $q 'RD_CAP_CLIPBOARD') -eq $null) 'and the clipboard is still a separate grant'

    $t = Invoke-Launcher -Tag 'trap' -Pre 'set RD_CAP_INPUT=1 &&'
    $ti = EnvOf $t 'RD_CAP_INPUT'
    # Round 5 found this by hand. Pinned here so it cannot come back as advice.
    Check ($ti -ne $null -and $ti -ne '1') ("the UNQUOTED form really does mis-set it -- host got '" + $ti + "', which capability_granted rejects")
    Check ($ti -eq '1 ') ("and the value is specifically '1' plus a trailing space (got '" + $ti + "')")

    # 5. no exe: refuse, say which file, and start nothing
    Write-Host ''
    Write-Host '  -- the missing-executable guard --'
    $n = Invoke-Launcher -Tag 'noexe' -NoExe
    Check ($n.Rc -eq 1) ("a missing host_app.exe exits 1, not 0 (got " + $n.Rc + ")")
    Check (-not $n.Ran) 'and nothing was started'
    Check ($n.Out -match 'host executable is not here') 'and it says so in words'
    Check ($n.Out -match 'host_app\.exe') 'and names the file it wanted'

    # ---- the diagnostic launcher, and the drift it could cause --------------
    #
    # run-console.bat exists so the host's console output can be captured:
    # run.bat ends in `start ""` and detaches, which loses the very line a P9
    # run is looking for. Windows round 13 had to declare a deviation for that.
    #
    # A THIRD LAUNCHER THAT GRANTS CAPABILITIES IS THE SHAPE OF THE 2026-09-05
    # DEFECT — two launchers, one fixed, one not. So it is not enough to test it
    # in isolation: the two must be asserted to deliver the SAME capability
    # environment. If they ever disagree, that is a failure here rather than a
    # blank phone for whoever picked the wrong one.
    Write-Host ''
    Write-Host '  -- run-console.bat: attached, and identical in what it grants --'

    if (-not (Test-Path $Console)) {
        Bad 'windows\run-console.bat is missing'
    } else {
        $c = Invoke-Launcher -Tag 'console' -LauncherFile $Console -Mutant
        Check ($c.Ran) 'it starts the host'
        $cs = EnvOf $c 'RD_CAP_SCREENSHOT'
        Check ($cs -eq '1') ("it RECEIVES RD_CAP_SCREENSHOT=1 (got '" + $cs + "')")
        Check ((EnvOf $c 'RD_CAP_INPUT') -eq $null) 'control is NOT granted by the diagnostic launcher either'
        Check ((EnvOf $c 'RD_CAP_CLIPBOARD') -eq $null) 'nor the clipboard'
        Check ($c.Rc -eq 0) ("it propagates the host exit code (got " + $c.Rc + ")")

        # The drift guard: same capabilities, both directions, by comparison
        # rather than by two separate hard-coded expectations.
        $capNames = @('RD_CAP_SCREENSHOT','RD_CAP_INPUT','RD_CAP_CLIPBOARD','RD_CAP_FILE')
        $diff = @()
        foreach ($n in $capNames) {
            $a = EnvOf $r $n; $b = EnvOf $c $n
            # ${n} braced deliberately: bare "$n:" parses as a scope-qualified
            # variable in PowerShell, not as the variable followed by a colon.
            if ($a -ne $b) { $diff += ("${n}: run.bat='" + $a + "' run-console.bat='" + $b + "'") }
        }
        Check ($diff.Count -eq 0) ("THE TWO LAUNCHERS GRANT THE SAME THING" + $(if ($diff.Count) { ' -- DRIFT: ' + ($diff -join '; ') } else { '' }))

        # And the reason it exists at all: attached, so output is capturable.
        Check ($c.Out -match 'running ATTACHED') 'it says it is running attached'
    }

    # ---- negative controls --------------------------------------------------
    Write-Host ''
    Write-Host '  -- negative controls: the harness must catch a broken launcher --'
    $text = Get-Content $Launcher -Raw

    function Red-Proof ([string]$name, [string]$mutated, [string]$var, $badValue) {
        $f = Join-Path $Work ("mutant-" + $name + ".bat")
        Set-Content -Path $f -Value $mutated -Encoding ASCII
        if ((Get-FileHash -Algorithm SHA256 $f).Hash -eq $LauncherHash) {
            Bad ("control '" + $name + "' did not change the launcher"); return
        }
        $m = Invoke-Launcher -Tag ("red-" + $name) -LauncherFile $f -Mutant
        $got = EnvOf $m $var
        if ($got -eq $badValue) { Ok ("caught: " + $name + " (" + $var + "='" + $got + "')") }
        else { Bad ("NOT caught: " + $name + " left " + $var + "='" + $got + "'") }
    }

    # The original defect: the grant is simply absent.
    Red-Proof 'grant-deleted' ($text -replace '(?m)^set RD_CAP_SCREENSHOT=1\r?$', 'rem removed') 'RD_CAP_SCREENSHOT' $null
    # The opposite error: a launcher that overrules deny-by-default.
    Red-Proof 'grants-input'  ($text -replace '(?m)^set RD_CAP_SCREENSHOT=1\r?$', "set RD_CAP_SCREENSHOT=1`r`nset RD_CAP_INPUT=1") 'RD_CAP_INPUT' '1'
    # The one a grep CANNOT catch: present, spelled correctly, and never reached
    # because the exe was already started. This is the whole reason for running
    # the launcher instead of reading it.
    Red-Proof 'grant-after-start' (($text -replace '(?m)^set RD_CAP_SCREENSHOT=1\r?$', 'rem moved below') -replace '(?m)^start "" "%RD_EXE%"\r?$', "start `"`" `"%RD_EXE%`"`r`nset RD_CAP_SCREENSHOT=1") 'RD_CAP_SCREENSHOT' $null

    Write-Host ''
    Write-Host ("  windows launcher: " + $script:Pass + " ok, " + $script:Fail + " failed")
}
finally {
    Remove-Item Env:\RD_STUB_OUT -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}

if ($script:Fail -ne 0) { exit 1 }
exit 0
