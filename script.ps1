
# read config file
#$Files = Get-Content -Path hashes | ConvertFrom-Json
$Files = ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wh4t4s3c/somenotes/master/hashes')) | ConvertFrom-Json

Write-Host "Installing..."

# verify and install
for (($i = 0); $i -lt $Files.entry.Count; $i++) {
	Write-Host "Installing" $Files.entry[$i].FileName
	if( (Get-FileHash $Files.entry[$i].FileName).Hash -ne $Files.entry[$i].Hash) { 
		Write-Host $Files.entry[$i].FileName "FAILED"
	} else {
		Start-Process -Wait $Files.entry[$i].FileName
	}

	Start-Sleep -Seconds $Files.entry[$i].Wait
}

Write-Host "WMI, what is installed?..."

#obtain instalaled packs
$Check = Get-WMIObject -Query "SELECT * FROM Win32_Product"

Write-Host "Check and clean up..."

#check if installed
for (($i = 0); $i -lt $Files.entry.Count; $i++) {
	Write-Host "Verifying" $Files.entry[$i].FileName
	if(-Not ($Check.Name -contains $Files.entry[$i].InstallName)) { 
		Write-Host $Files.entry[$i].FileName "----------------FAILED" 
	}
	Write-Host "Remove-Item -Path $Files.entry[$i].FileName -Force"
	#Remove-Item -Path $Files.entry[$i].FileName -Force
}
