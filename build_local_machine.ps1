#!/usr/bin/env pwsh

$env:CI = 'true'
$env:IS_STABLE_BUILD = 'true'

.\build.ps1 -ci