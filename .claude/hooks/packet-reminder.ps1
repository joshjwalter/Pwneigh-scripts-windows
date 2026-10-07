# UserPromptSubmit hook: when a prompt looks like it shares the competition packet, remind Claude to run the
# packet-intake skill, so nothing in the packet that affects the script gets missed. Never blocks; prints nothing otherwise.
$ErrorActionPreference = 'SilentlyContinue'
$prompt = "$(([Console]::In.ReadToEnd() | ConvertFrom-Json).prompt)"
if ($prompt -notmatch '(?i)packet|rules of engagement|\bROE\b|team info|scoring (engine|checks?|info)|\.pdf\b') { exit 0 }
$skill = Join-Path (Split-Path $PSScriptRoot -Parent) 'skills\packet-intake\SKILL.md'
Write-Output "If this prompt shares the HPCC4 competition packet (rules, box list, scoring info), invoke the packet-intake skill, or read and follow $skill, before anything else. If it doesn't, ignore this."
exit 0
