# Copy to caddy.env.ps1, edit, then dot-source it in the SAME PowerShell
# session that validates or starts Caddy:
#   . .\caddy.env.ps1
#
# Generate the hash interactively on the VPS so plaintext stays out of history/process arguments:
#   $env:OBFUSCAN_BASIC_AUTH_HASH = & C:\Caddy\caddy.exe hash-password

$env:OBFUSCAN_DOMAIN = 'scan.example.com'
$env:ACME_EMAIL = 'security@example.com'
$env:OBFUSCAN_BASIC_AUTH_USER = 'obfuscan-admin'
$env:OBFUSCAN_BASIC_AUTH_HASH = 'REPLACE_WITH_CADDY_BCRYPT_HASH'
