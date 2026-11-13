<#
  Laboratorio SOC - script unico de operacao (Windows PowerShell 5.1+)

  Uso (na pasta do projeto):
    powershell -ExecutionPolicy Bypass -File .\lab.ps1 <comando> [-Id N]

  Comandos:
    preparar     cria o .env, gera certificados do Wazuh e constroi as imagens
    fase1        sobe firewall, server e cliente e testa ping/rotas/internet
    fase2        testa as regras do firewall (liberado x bloqueado)
    fase3        sobe Wazuh + Suricata e valida eve.json, syslog e agentes
    fase5        sobe Ollama + ai-analyst (baixa o modelo na primeira vez)
    status       estado dos containers e saude (testes/saidas/status_containers.txt)
    teste -Id N  executa/registra o teste N (1 a 6) e extrai as evidencias
    evidencias -Id N   extrai novamente as evidencias do teste N (apos a IA terminar)
    prints       gera as capturas de tela em prints/
    logs         mostra os ultimos logs dos servicos principais
    parar        para o laboratorio (mantem dados)
  Todas as saidas ficam em testes/saidas/.
#>
param(
  [Parameter(Position = 0)][string]$Comando = "ajuda",
  [int]$Id = 0,
  [int]$Espera = 150
)

$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot
$Saidas = Join-Path $PSScriptRoot "testes\saidas"
New-Item -ItemType Directory -Force -Path $Saidas | Out-Null

function Agora { Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz" }

function Titulo([string]$t) {
  Write-Host ""
  Write-Host ("=" * 70) -ForegroundColor Cyan
  Write-Host " $t" -ForegroundColor Cyan
  Write-Host ("=" * 70) -ForegroundColor Cyan
}

# Executa um comando, mostra na tela e grava "$ comando" + saida no arquivo
function Executar([string]$Arquivo, [string]$Cmd) {
  $dest = Join-Path $Saidas $Arquivo
  $cab = "[$(Agora)] PS> $Cmd"
  Write-Host $cab -ForegroundColor Yellow
  Add-Content -Path $dest -Value $cab -Encoding UTF8
  $out = cmd /c "$Cmd 2>&1"
  $out | ForEach-Object { Write-Host $_ }
  Add-Content -Path $dest -Value ($out | Out-String) -Encoding UTF8
  Add-Content -Path $dest -Value "" -Encoding UTF8
}

function NovoArquivo([string]$Arquivo) {
  $dest = Join-Path $Saidas $Arquivo
  Set-Content -Path $dest -Value "# $Arquivo - gerado em $(Agora)" -Encoding UTF8
  return $Arquivo
}

function LerEnv {
  $vals = @{}
  if (Test-Path ".env") {
    Get-Content ".env" | Where-Object { $_ -match "^\s*[A-Za-z_][A-Za-z0-9_]*=" } | ForEach-Object {
      $k, $v = $_ -split "=", 2
      $vals[$k.Trim()] = $v.Trim()
    }
  }
  return $vals
}

function NovoSegredo([int]$n = 24) {
  $chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  -join (1..$n | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Preparar {
  Titulo "Preparar: .env, vm.max_map_count, certificados e imagens"
  if (-not (Test-Path ".env")) {
    $txt = Get-Content ".env.example" -Raw
    $txt = $txt -replace "FW_API_TOKEN=troque-este-token", ("FW_API_TOKEN=" + (NovoSegredo 32))
    $txt = $txt -replace "LAB_SSH_PASSWORD=troque-esta-senha", ("LAB_SSH_PASSWORD=" + (NovoSegredo 16))
    [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot ".env"), $txt)
    Write-Host ".env criado a partir do .env.example (token e senha SSH aleatorios)." -ForegroundColor Green
  } else {
    Write-Host ".env ja existe - mantido." -ForegroundColor Green
  }
  $f = NovoArquivo "00_preparar.txt"
  Executar $f "docker run --rm alpine:3.20 sysctl vm.max_map_count"
  $mm = (cmd /c "docker run --rm alpine:3.20 sysctl -n vm.max_map_count 2>&1") | Select-Object -Last 1
  if ([int]$mm -lt 262144) {
    Write-Host ""
    Write-Host "ATENCAO: vm.max_map_count=$mm (o Wazuh indexer precisa de 262144)." -ForegroundColor Red
    Write-Host "Rode (altera so a VM do Docker, volta ao padrao ao reiniciar o Docker Desktop):" -ForegroundColor Red
    Write-Host "  wsl -d docker-desktop -u root sysctl -w vm.max_map_count=262144" -ForegroundColor White
    Write-Host "Depois rode .\lab.ps1 preparar de novo." -ForegroundColor Red
    return
  }
  if (-not (Test-Path "wazuh\config\wazuh_indexer_ssl_certs\root-ca.pem")) {
    Executar $f "docker compose -f wazuh/generate-indexer-certs.yml run --rm generator"
  } else {
    Write-Host "Certificados do Wazuh ja existem." -ForegroundColor Green
  }
  Executar $f "docker compose build"
  Executar $f "docker compose pull suricata wazuh.manager wazuh.indexer wazuh.dashboard ollama wazuh-route"
  Write-Host "Pronto. Proximo passo: .\lab.ps1 fase1" -ForegroundColor Green
}

function Fase1 {
  Titulo "Fase 1 - Infra base: firewall, server, cliente"
  $f = NovoArquivo "01_fase1_infra.txt"
  Executar $f "docker compose up -d firewall server cliente"
  Start-Sleep -Seconds 8
  Executar $f "docker compose ps firewall server cliente"
  Executar $f "docker network inspect lab-soc_lan --format ""{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}"""
  Executar $f "docker compose exec -T cliente ip route"
  Executar $f "docker compose exec -T server ip route"
  Executar $f "docker compose exec -T cliente ping -c 3 192.168.10.1"
  Executar $f "docker compose exec -T cliente ping -c 3 192.168.10.10"
  Executar $f "docker compose exec -T cliente ping -c 3 1.1.1.1"
  Executar $f "docker compose exec -T cliente ip route get 1.1.1.1"
  Executar $f "docker compose exec -T cliente dig +short example.com"
  Executar $f "docker compose exec -T cliente curl -sS -o /dev/null -w ""HTTP %{http_code} via firewall\n"" http://example.com"
  Executar $f "docker compose exec -T cliente curl -sS -m 5 http://192.168.10.10/"
  Executar $f "docker compose exec -T firewall nft list table ip nat"
  Executar $f "docker compose logs --tail 20 firewall"
  Write-Host "Saida em testes\saidas\$f" -ForegroundColor Green
}

function Fase2 {
  Titulo "Fase 2 - Firewall: liberado x bloqueado, NAT e logs"
  $f = NovoArquivo "02_fase2_firewall.txt"
  Executar $f "docker compose exec -T cliente curl -sS -o /dev/null -w ""LIBERADO http %{http_code}\n"" http://example.com"
  Executar $f "docker compose exec -T cliente curl -sS -o /dev/null -w ""LIBERADO https %{http_code}\n"" https://example.com"
  Executar $f "docker compose exec -T cliente sh -c ""nc -vz -w 3 1.1.1.1 23 || echo BLOQUEADO: telnet externo"""
  Executar $f "docker compose exec -T cliente sh -c ""nc -vz -w 3 172.30.0.12 5601 || echo BLOQUEADO: LAN para dashboard do Wazuh"""
  Executar $f "docker compose exec -T firewall fw-status"
  Write-Host "Saida em testes\saidas\$f" -ForegroundColor Green
}

function Fase3 {
  Titulo "Fases 3 e 4 - Wazuh (single-node) + Suricata"
  $f = NovoArquivo "03_fase3_wazuh_suricata.txt"
  Executar $f "docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard wazuh-route suricata"
  Write-Host "Aguardando o Wazuh iniciar (2 a 4 minutos)..." -ForegroundColor Yellow
  Start-Sleep -Seconds 150
  Executar $f "docker compose ps"
  Executar $f "docker compose exec -T wazuh.manager ip route"
  Executar $f "docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l"
  Executar $f "docker compose logs --tail 30 suricata"
  Executar $f "docker compose exec -T wazuh.manager sh -c ""tail -n 3 /var/log/suricata/eve.json"""
  Executar $f "docker compose exec -T wazuh.manager wc -l /var/log/suricata/eve.json"
  Executar $f "docker compose exec -T cliente sh -c ""nc -vz -w 2 1.1.1.1 23 || true"""
  Start-Sleep -Seconds 10
  Executar $f "docker compose exec -T wazuh.manager sh -c ""grep -h lab-fw /var/ossec/logs/alerts/alerts.json | tail -n 2"""
  Executar $f "docker compose exec -T wazuh.manager sh -c ""grep -c syscheck /var/ossec/logs/alerts/alerts.json"""
  Write-Host ""
  Write-Host "Dashboard: https://localhost:$((LerEnv)['WAZUH_DASHBOARD_PORT'])  (usuario/senha no .env: INDEXER_USERNAME / INDEXER_PASSWORD)" -ForegroundColor Green
  Write-Host "Saida em testes\saidas\$f" -ForegroundColor Green
}

function Fase5 {
  Titulo "Fase 5 - IA: Ollama + ai-analyst"
  $f = NovoArquivo "05_fase5_ia.txt"
  Executar $f "docker compose up -d ollama ai-analyst"
  Write-Host "Na primeira vez o modelo e baixado (varios GB). Acompanhe com: docker compose logs -f ai-analyst" -ForegroundColor Yellow
  Start-Sleep -Seconds 20
  Executar $f "docker compose logs --tail 30 ai-analyst"
  Executar $f "docker compose exec -T ollama ollama list"
  Write-Host "Saida em testes\saidas\$f" -ForegroundColor Green
}

function Status {
  $f = NovoArquivo "status_containers.txt"
  Executar $f "docker compose ps --format ""table {{.Name}}\t{{.Image}}\t{{.Status}}"""
  Executar $f "docker network ls --filter name=lab-soc"
  Executar $f "docker stats --no-stream --format ""table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"""
  if (Test-Path "ia\saude.md") { Get-Content "ia\saude.md" | Select-Object -First 15 | ForEach-Object { Write-Host $_ } }
}

$Testes = @{
  1 = @{ Nome = "Varredura de portas do Cliente para o Server"; Auto = $false;
         Esperado = "Suricata (ET SCAN / LAB 9100002) e regra do lab 100211 com origem 192.168.10.20; analise da IA como reconhecimento (T1046)" }
  2 = @{ Nome = "Forca bruta SSH no Server"; Auto = $false;
         Esperado = "Wazuh sshd 5710/5760 e 5763 (nivel 10), Suricata LAB 9100001 / regra 100210; IA: T1110, gravidade alta" }
  3 = @{ Nome = "Assinatura de teste do Suricata (testmynids.org)"; Auto = $true;
         Cmd = "docker compose exec -T cliente curl -s -m 15 http://testmynids.org/uid/index.html";
         Esperado = "Suricata GPL ATTACK_RESPONSE id check returned root (sid 2100498) no Wazuh" }
  4 = @{ Nome = "Alteracao de arquivo monitorado (FIM)"; Auto = $true;
         Cmd = "docker compose exec -T server sh -c ""echo '<!-- teste FIM lab -->' >> /var/www/html/index.html; echo lab_fim_teste=1 > /etc/lab-fim-teste.conf""";
         Esperado = "Wazuh syscheck: 550 (arquivo modificado) em /var/www/html/index.html e 554 (arquivo criado) em /etc" }
  5 = @{ Nome = "Trafego bloqueado pelo firewall (LAN -> servicos da gerencia)"; Auto = $true;
         Cmd = "docker compose exec -T cliente sh -c ""for r in 1 2 3 4 5; do for p in 22 5601 9200 11434 55000; do nc -z -w 1 172.30.0.12 `$p; done; done; echo fim""";
         Esperado = "Firewall descarta e registra (FW-DROP); Wazuh 100101 (nivel 5) e 100102 (nivel 10, muitas conexoes bloqueadas da mesma origem)" }
  6 = @{ Nome = "Reincidencia do teste 2 (forca bruta SSH)"; Auto = $false;
         Esperado = "Mesmos alertas do teste 2; IA marca reincidencia=SIM e recomenda (ou aplica, com AUTO_BLOCK=true) o bloqueio de 192.168.10.20" }
}

function Teste([int]$N) {
  if (-not $Testes.ContainsKey($N)) { Write-Host "Use -Id 1 a 6" -ForegroundColor Red; return }
  $t = $Testes[$N]
  $tid = "T$N"
  Titulo "Teste $tid - $($t.Nome)"
  $f = NovoArquivo "${tid}_saida.txt"
  $inicio = Agora
  if ($t.Auto) {
    $cmdUsado = $t.Cmd
    Executar $f $t.Cmd
  } else {
    Write-Host "Este teste e executado POR VOCE, dentro do laboratorio, contra 192.168.10.10." -ForegroundColor Yellow
    Write-Host "1) Abra outro terminal na pasta do projeto e entre no cliente:" -ForegroundColor Yellow
    Write-Host "     docker compose exec cliente bash" -ForegroundColor White
    Write-Host "2) Rode o comando do teste e aguarde terminar." -ForegroundColor Yellow
    $cmdUsado = Read-Host "Cole aqui o comando que voce vai executar (para o registro)"
    Read-Host "Pressione ENTER quando o comando TERMINAR"
    Add-Content -Path (Join-Path $Saidas $f) -Value "[$inicio] comando informado: $cmdUsado" -Encoding UTF8
  }
  $fim = Agora
  $janela = @{ id = $tid; nome = $t.Nome; inicio = $inicio; fim = $fim; comando = $cmdUsado; esperado = $t.Esperado }
  $janela | ConvertTo-Json | Set-Content -Path (Join-Path $Saidas "${tid}_janela.json") -Encoding UTF8
  Write-Host "Inicio $inicio  Fim $fim. Aguardando $Espera s para os alertas e a analise da IA..." -ForegroundColor Yellow
  Start-Sleep -Seconds $Espera
  Evidencias $N
}

function Evidencias([int]$N) {
  $tid = "T$N"
  $arq = Join-Path $Saidas "${tid}_janela.json"
  if (-not (Test-Path $arq)) { Write-Host "Rode antes: .\lab.ps1 teste -Id $N" -ForegroundColor Red; return }
  $j = Get-Content $arq -Raw | ConvertFrom-Json
  $cmdTxt = ($j.comando -replace '"', "'")
  $dargs = @("compose", "exec", "-T", "ai-analyst", "python", "-m", "analyst.evidencias",
            "--id", $tid, "--nome", $j.nome, "--inicio", $j.inicio, "--fim", $j.fim,
            "--comando", $cmdTxt, "--esperado", $j.esperado)
  & docker @dargs
  Write-Host "Evidencias: testes\$tid.md" -ForegroundColor Green
}

function Prints {
  Titulo "Fase 7 - capturas de tela (Playwright headless)"
  Status
  $f = NovoArquivo "nft_ruleset.txt"
  Executar $f "docker compose exec -T firewall nft list ruleset"
  $f2 = NovoArquivo "firewall_log.txt"
  Executar $f2 "docker compose exec -T firewall tail -n 40 /var/log/lab-fw/firewall.log"
  $f3 = NovoArquivo "agentes_wazuh.txt"
  Executar $f3 "docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l"
  docker compose --profile prints run --rm prints
  Write-Host "Prints em prints\ (veja prints\prints_log.txt para o que precisar ser manual)" -ForegroundColor Green
}

switch ($Comando.ToLower()) {
  "preparar"   { Preparar }
  "fase1"      { Fase1 }
  "fase2"      { Fase2 }
  "fase3"      { Fase3 }
  "fase4"      { Fase3 }
  "fase5"      { Fase5 }
  "status"     { Status }
  "teste"      { Teste $Id }
  "evidencias" { Evidencias $Id }
  "prints"     { Prints }
  "logs"       { docker compose logs --tail 30 firewall suricata wazuh.manager ai-analyst }
  "parar"      { docker compose stop }
  default      { Get-Help $PSCommandPath -Detailed | Out-String | Write-Host; Write-Host "Ex.: .\lab.ps1 preparar" }
}
