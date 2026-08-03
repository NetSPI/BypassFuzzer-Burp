[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GradleArgs = @('clean', 'build')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$jdkRoot = Join-Path $projectRoot '.gradle\jdks'
$jdkHome = Join-Path $jdkRoot 'temurin-17'

function Get-JavaMajorVersion([string]$java) {
    $output = (& $java -version 2>&1 | Out-String)
    if ($output -match 'version "([0-9]+)') { return [int]$Matches[1] }
    return 0
}

function Find-Java {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:JAVA_HOME) { $candidates.Add((Join-Path $env:JAVA_HOME 'bin\java.exe')) }
    $pathJava = Get-Command java.exe -ErrorAction SilentlyContinue
    if ($pathJava) { $candidates.Add($pathJava.Source) }

    foreach ($root in @(
        (Join-Path $env:ProgramFiles 'Java'),
        (Join-Path $env:ProgramFiles 'Eclipse Adoptium'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Eclipse Adoptium')
    )) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { $candidates.Add((Join-Path $_.FullName 'bin\java.exe')) }
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ((Test-Path -LiteralPath $candidate) -and (Get-JavaMajorVersion $candidate) -ge 17) {
            return $candidate
        }
    }
    return $null
}

function Install-Java {
    $arch = if ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } elseif ([Environment]::Is64BitOperatingSystem) { 'x64' } else { throw 'A 32-bit Windows JDK is not supported by this build.' }
    $url = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/$arch/jdk/hotspot/normal/eclipse"
    $archive = Join-Path $env:TEMP 'bypassfuzzer-temurin-17.zip'
    New-Item -ItemType Directory -Force -Path $jdkRoot | Out-Null
    Write-Host 'No Java 17+ installation found; downloading Temurin 17 for this project...'
    Invoke-WebRequest -Uri $url -OutFile $archive -TimeoutSec 120
    $extractRoot = Join-Path $jdkRoot 'download'
    if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
    Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force
    $foundHome = Get-ChildItem -LiteralPath $extractRoot -Directory | Select-Object -First 1
    if (-not $foundHome) { throw 'The Java download did not contain a JDK directory.' }
    if (Test-Path -LiteralPath $jdkHome) { Remove-Item -LiteralPath $jdkHome -Recurse -Force }
    Move-Item -LiteralPath $foundHome.FullName -Destination $jdkHome
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
    Remove-Item -LiteralPath $archive -Force
    return (Join-Path $jdkHome 'bin\java.exe')
}

$java = Find-Java
if (-not $java) {
    $java = Install-Java
}
$env:JAVA_HOME = Split-Path -Parent (Split-Path -Parent $java)
& (Join-Path $projectRoot 'gradlew.bat') @GradleArgs
exit $LASTEXITCODE
