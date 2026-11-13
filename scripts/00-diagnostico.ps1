# Diagnostico do host para o laboratorio SOC (somente leitura - nao altera nada)
# Uso (PowerShell, na pasta Implementacao):
#   powershell -ExecutionPolicy Bypass -File .\scripts\00-diagnostico.ps1
$ErrorActionPreference = 'Continue'
$env:WSL_UTF8 = '1'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'diagnostico\diagnostico.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
function Sec($t) { "`n===== $t =====" }
& {
  Sec 'Data'
  Get-Date -Format o
  Sec 'Sistema'
  Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List | Out-String
  $cs = Get-CimInstance Win32_ComputerSystem
  "RAM_GB: {0:N1}" -f ($cs.TotalPhysicalMemory / 1GB)
  "HypervisorPresent: $($cs.HypervisorPresent)"
  Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, VirtualizationFirmwareEnabled | Format-List | Out-String
  Sec 'GPU'
  Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion | Format-List | Out-String
  if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) { nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv }
  Sec 'Disco'
  Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{n='LivreGB';e={[math]::Round($_.Free/1GB,1)}} | Format-Table | Out-String
  Sec 'Ferramentas'
  foreach ($c in 'docker','git','python','py','ollama','wsl','VBoxManage') {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    "{0,-12} {1}" -f $c, $(if ($cmd) { $cmd.Source } else { 'NAO ENCONTRADO' })
  }
  if (Test-Path 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe') { 'VirtualBox: instalado' } else { 'VirtualBox: nao encontrado' }
  Sec 'Versoes'
  docker version --format 'docker server {{.Server.Version}} / {{.Server.Os}}' 2>&1
  docker compose version 2>&1
  git --version 2>&1
  python --version 2>&1
  ollama --version 2>&1
  Sec 'WSL'
  wsl --status 2>&1
  wsl -l -v 2>&1
  $wc = Join-Path $env:USERPROFILE '.wslconfig'
  if (Test-Path $wc) { ".wslconfig existe:"; Get-Content $wc } else { '.wslconfig: nao existe' }
  Sec 'Docker info'
  docker info --format 'CPUs={{.NCPU}} MemBytes={{.MemTotal}} Kernel={{.KernelVersion}} OS={{.OperatingSystem}}' 2>&1
  Sec 'vm.max_map_count (VM do Docker)'
  docker run --rm alpine:3.20 sysctl vm.max_map_count 2>&1
  Sec 'KVM dentro do Docker'
  docker run --rm --privileged alpine:3.20 sh -c "ls -l /dev/kvm 2>&1 || echo SEM_KVM" 2>&1
  Sec 'GPU no Docker'
  if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) { docker run --rm --gpus all alpine:3.20 sh -c "ls /dev/dxg /usr/lib/wsl 2>&1" 2>&1 } else { 'sem nvidia-smi no host' }
  Sec 'Portas em uso no host'
  foreach ($p in 443,5601,9200,55000,1514,1515,514,11434,8080,8088) {
    $u = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    "{0,-6} {1}" -f $p, $(if ($u) { 'EM USO' } else { 'livre' })
  }
} *>&1 | Out-File -FilePath $out -Encoding utf8
Write-Host "Diagnostico salvo em $out" -ForegroundColor Green
