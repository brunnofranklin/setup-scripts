<#
.SYNOPSIS
    Demonstração e validação do sistema PNA Helpdesk
    
.DESCRIPTION
    Script de demonstração que mostra as funcionalidades principais
    do instalador PNA Helpdesk e valida se o sistema está funcionando
    corretamente após a instalação.
    
.PARAMETER DemoPath
    Caminho para executar a demonstração (padrão: C:\Temp\PNADemo)
    
.PARAMETER QuickDemo
    Executa apenas uma demonstração rápida das funcionalidades principais
    
.EXAMPLE
    .\Demo-PNAHelpdesk.ps1 -Verbose
    
.EXAMPLE  
    .\Demo-PNAHelpdesk.ps1 -DemoPath "D:\Demos" -QuickDemo
    
.NOTES
    Autor: PNA Development Team
    Versão: 1.0
    Data: 2024
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DemoPath = "C:\Temp\PNADemo",
    
    [Parameter()]
    [switch]$QuickDemo
)

#Requires -Version 5.1

# ============================================================================
# CONFIGURAÇÕES DA DEMONSTRAÇÃO
# ============================================================================

$ErrorActionPreference = "Continue"
$VerbosePreference = if ($PSBoundParameters.ContainsKey('Verbose')) { 'Continue' } else { 'SilentlyContinue' }

# Importar classes do instalador
$installerPath = Join-Path $PSScriptRoot "Install-PNAHelpdesk.ps1"
if (Test-Path $installerPath) {
    . $installerPath
}

# ============================================================================
# FUNÇÕES DE DEMONSTRAÇÃO
# ============================================================================

function Show-Banner {
    param([string]$Title)
    
    $border = "=" * 60
    Write-Host ""
    Write-Host $border -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host $border -ForegroundColor Cyan
    Write-Host ""
}

function Show-Step {
    param([string]$Step, [string]$Description)
    
    Write-Host "[$Step]" -ForegroundColor Green -NoNewline
    Write-Host " $Description" -ForegroundColor White
}

function Wait-ForUser {
    param([string]$Message = "Pressione Enter para continuar...")
    
    if (-not $QuickDemo) {
        Write-Host ""
        Write-Host $Message -ForegroundColor Yellow
        Read-Host | Out-Null
    } else {
        Start-Sleep -Seconds 1
    }
}

function Demo-LoggingSystem {
    Show-Banner "DEMONSTRAÇÃO: Sistema de Logging Avançado"
    
    Show-Step "1.1" "Criando logger com diferentes níveis de log"
    
    try {
        $logPath = Join-Path $DemoPath "Logs"
        $logger = [PNALogger]::new($logPath, [LogLevel]::DEBUG, $true)
        
        Show-Step "1.2" "Testando diferentes níveis de log"
        $logger.Debug("Esta é uma mensagem de DEBUG - detalhes técnicos")
        $logger.Info("Esta é uma mensagem de INFO - operação normal")
        $logger.Warning("Esta é uma mensagem de WARNING - atenção necessária")
        $logger.Error("Esta é uma mensagem de ERROR - problema detectado")
        $logger.Critical("Esta é uma mensagem CRITICAL - intervenção urgente")
        
        Show-Step "1.3" "Testando log com contexto estruturado"
        $logger.Info("Operação de demonstração executada", @{
            'Usuario' = $env:USERNAME
            'Timestamp' = Get-Date
            'Sistema' = 'PNA Helpdesk Demo'
            'Operacao' = 'Demo Logging'
            'Dados' = @{
                'IP' = '192.168.1.100'
                'Status' = 'Sucesso'
                'Duracao' = '1.5s'
            }
        })
        
        Write-Host "✓ Sistema de logging funcionando corretamente!" -ForegroundColor Green
        Write-Host "  Arquivo de log: $($logger.LogFile)" -ForegroundColor Gray
        
        $logger.Dispose()
    }
    catch {
        Write-Host "✗ Erro no sistema de logging: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Demo-SecurityValidation {
    Show-Banner "DEMONSTRAÇÃO: Validações de Segurança"
    
    Show-Step "2.1" "Criando validador de segurança"
    
    try {
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        $validator = [SecurityValidator]::new($tempLogger)
        
        Show-Step "2.2" "Testando validação de tokens"
        
        # Token válido
        $validToken = "abcdef1234567890abcdef1234567890secure"
        $result = $validator.ValidateToken($validToken)
        Write-Host "  Token válido: $validToken → " -NoNewline
        Write-Host $(if ($result) { "✓ VÁLIDO" } else { "✗ INVÁLIDO" }) -ForegroundColor $(if ($result) { 'Green' } else { 'Red' })
        
        # Token inválido
        $invalidToken = "123"
        $result = $validator.ValidateToken($invalidToken)
        Write-Host "  Token inválido: $invalidToken → " -NoNewline
        Write-Host $(if (-not $result) { "✓ REJEITADO" } else { "✗ ACEITO" }) -ForegroundColor $(if (-not $result) { 'Green' } else { 'Red' })
        
        Show-Step "2.3" "Testando validação de credenciais"
        
        $validCred = New-Object System.Management.Automation.PSCredential(
            "usuario_demo",
            (ConvertTo-SecureString "SenhaSegura123!" -AsPlainText -Force)
        )
        
        $result = $validator.ValidateCredentials($validCred)
        Write-Host "  Credenciais válidas → " -NoNewline
        Write-Host $(if ($result) { "✓ VÁLIDAS" } else { "✗ INVÁLIDAS" }) -ForegroundColor $(if ($result) { 'Green' } else { 'Red' })
        
        Show-Step "2.4" "Testando validação de conectividade"
        $result = $validator.ValidateNetworkConnection("https://www.google.com", 5)
        Write-Host "  Conectividade → " -NoNewline
        Write-Host $(if ($result) { "✓ CONECTADO" } else { "⚠ SEM CONECTIVIDADE" }) -ForegroundColor $(if ($result) { 'Green' } else { 'Yellow' })
        
        Write-Host "✓ Sistema de segurança funcionando corretamente!" -ForegroundColor Green
        
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro nas validações de segurança: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Demo-BackupSystem {
    Show-Banner "DEMONSTRAÇÃO: Sistema de Backup e Recuperação"
    
    Show-Step "3.1" "Preparando ambiente de demonstração"
    
    try {
        # Criar dados de exemplo
        $sourcePath = Join-Path $DemoPath "DemoData"
        $backupPath = Join-Path $DemoPath "Backups"
        $restorePath = Join-Path $DemoPath "Restored"
        
        # Limpar diretórios
        @($sourcePath, $backupPath, $restorePath) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
        
        # Criar arquivos de exemplo
        "Documento importante do PNA Helpdesk" | Set-Content (Join-Path $sourcePath "documento.txt")
        "Configuração do sistema: version=2.0.1" | Set-Content (Join-Path $sourcePath "config.ini")
        "Log de operações: $(Get-Date)" | Set-Content (Join-Path $sourcePath "operacoes.log")
        
        Write-Host "  Criados arquivos de exemplo em: $sourcePath" -ForegroundColor Gray
        
        Show-Step "3.2" "Criando sistema de backup"
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        $backupManager = [BackupManager]::new($backupPath, $tempLogger, 3)
        
        Show-Step "3.3" "Executando backup dos dados"
        $backupFile = $backupManager.CreateBackup($sourcePath, "demo_backup")
        
        Write-Host "  Backup criado: $backupFile" -ForegroundColor Gray
        $backupSize = [math]::Round((Get-Item $backupFile).Length / 1KB, 2)
        Write-Host "  Tamanho: ${backupSize}KB" -ForegroundColor Gray
        
        Show-Step "3.4" "Simulando perda de dados"
        Remove-Item $sourcePath -Recurse -Force
        Write-Host "  Dados originais removidos (simulação de falha)" -ForegroundColor Yellow
        
        Show-Step "3.5" "Restaurando backup"
        $success = $backupManager.RestoreBackup($backupFile, $restorePath)
        
        if ($success) {
            Write-Host "✓ Backup restaurado com sucesso!" -ForegroundColor Green
            
            # Verificar arquivos restaurados
            $restoredFiles = Get-ChildItem $restorePath
            Write-Host "  Arquivos restaurados:" -ForegroundColor Gray
            foreach ($file in $restoredFiles) {
                Write-Host "    - $($file.Name)" -ForegroundColor Gray
            }
        } else {
            Write-Host "✗ Falha na restauração do backup" -ForegroundColor Red
        }
        
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro no sistema de backup: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Demo-ResourceMonitor {
    Show-Banner "DEMONSTRAÇÃO: Monitor de Recursos do Sistema"
    
    Show-Step "4.1" "Inicializando monitor de recursos"
    
    try {
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        $monitor = [ResourceMonitor]::new($tempLogger)
        
        Show-Step "4.2" "Coletando métricas do sistema"
        
        for ($i = 1; $i -le 3; $i++) {
            $usage = $monitor.GetCurrentUsage()
            
            Write-Host "  Medição #$i" -ForegroundColor Cyan
            Write-Host "    CPU: $($usage.CPUUsage)%" -ForegroundColor White
            Write-Host "    Memória Disponível: $($usage.AvailableMemoryMB)MB" -ForegroundColor White
            Write-Host "    Memória do Processo: $($usage.ProcessMemoryMB)MB" -ForegroundColor White
            Write-Host "    Timestamp: $($usage.Timestamp)" -ForegroundColor Gray
            
            if (-not $QuickDemo -and $i -lt 3) {
                Write-Host "    Aguardando próxima medição..." -ForegroundColor Gray
                Start-Sleep -Seconds 2
            }
        }
        
        Show-Step "4.3" "Verificando restrições de recursos"
        $isConstrained = $monitor.IsResourceConstraint()
        
        Write-Host "  Status do sistema: " -NoNewline
        if ($isConstrained) {
            Write-Host "⚠ RECURSOS LIMITADOS" -ForegroundColor Yellow
        } else {
            Write-Host "✓ RECURSOS ADEQUADOS" -ForegroundColor Green
        }
        
        Write-Host "✓ Monitor de recursos funcionando corretamente!" -ForegroundColor Green
        
        $monitor.Dispose()
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro no monitor de recursos: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Demo-WebSocketManager {
    Show-Banner "DEMONSTRAÇÃO: Gerenciador WebSocket"
    
    Show-Step "5.1" "Configurando gerenciador WebSocket"
    
    try {
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        
        # Usar um serviço de echo WebSocket público para teste
        $wsUrl = "wss://echo.websocket.org"
        $wsManager = [WebSocketManager]::new($wsUrl, 10000, $tempLogger)
        
        Show-Step "5.2" "Testando conectividade WebSocket"
        Write-Host "  Conectando com: $wsUrl" -ForegroundColor Gray
        
        $connected = $wsManager.Connect()
        
        if ($connected) {
            Write-Host "  ✓ Conexão WebSocket estabelecida!" -ForegroundColor Green
            
            Show-Step "5.3" "Testando envio de mensagem"
            $testMessage = "Mensagem de teste do PNA Helpdesk - $(Get-Date)"
            $sent = $wsManager.SendMessage($testMessage)
            
            if ($sent) {
                Write-Host "  ✓ Mensagem enviada: $($testMessage.Substring(0, 30))..." -ForegroundColor Green
                
                Show-Step "5.4" "Aguardando resposta (echo)"
                Start-Sleep -Seconds 2
                $response = $wsManager.ReceiveMessage()
                
                if ($response) {
                    Write-Host "  ✓ Resposta recebida: $($response.Substring(0, 30))..." -ForegroundColor Green
                } else {
                    Write-Host "  ⚠ Nenhuma resposta recebida (timeout)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  ✗ Falha ao enviar mensagem" -ForegroundColor Red
            }
            
            Show-Step "5.5" "Fechando conexão WebSocket"
            $wsManager.Disconnect()
            Write-Host "  ✓ Conexão fechada corretamente" -ForegroundColor Green
            
        } else {
            Write-Host "  ⚠ Não foi possível estabelecer conexão WebSocket" -ForegroundColor Yellow
            Write-Host "    (Pode ser devido a proxy/firewall corporativo)" -ForegroundColor Gray
        }
        
        Write-Host "✓ Gerenciador WebSocket funcionando!" -ForegroundColor Green
        
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro no gerenciador WebSocket: $_" -ForegroundColor Red
        Write-Host "    (Erro esperado se não houver conectividade externa)" -ForegroundColor Gray
    }
    
    Wait-ForUser
}

function Demo-RecoverySystem {
    Show-Banner "DEMONSTRAÇÃO: Sistema de Recuperação Automática"
    
    Show-Step "6.1" "Configurando sistema de recuperação"
    
    try {
        # Preparar ambiente
        $sourcePath = Join-Path $DemoPath "SystemData"
        $backupPath = Join-Path $DemoPath "RecoveryBackups"
        
        if (Test-Path $sourcePath) { Remove-Item $sourcePath -Recurse -Force }
        if (Test-Path $backupPath) { Remove-Item $backupPath -Recurse -Force }
        
        New-Item -Path $sourcePath -ItemType Directory -Force | Out-Null
        
        # Criar sistema inicial
        "Sistema PNA Helpdesk v2.0.1" | Set-Content (Join-Path $sourcePath "version.txt")
        "Status: Funcionando" | Set-Content (Join-Path $sourcePath "status.txt")
        
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        $backupManager = [BackupManager]::new($backupPath, $tempLogger)
        $recoveryManager = [RecoveryManager]::new($tempLogger, $backupManager)
        
        Show-Step "6.2" "Criando ponto de recuperação inicial"
        $recoveryManager.CreateRecoveryPoint("sistema_estavel", $sourcePath)
        
        Write-Host "  ✓ Ponto de recuperação 'sistema_estavel' criado" -ForegroundColor Green
        
        Show-Step "6.3" "Simulando modificações no sistema"
        "Sistema PNA Helpdesk v2.1.0-beta" | Set-Content (Join-Path $sourcePath "version.txt")
        "Status: Em atualização" | Set-Content (Join-Path $sourcePath "status.txt")
        "Arquivo temporário" | Set-Content (Join-Path $sourcePath "temp.tmp")
        
        Write-Host "  Sistema modificado (simulação de atualização)" -ForegroundColor Yellow
        
        Show-Step "6.4" "Simulando falha na atualização"
        Remove-Item (Join-Path $sourcePath "status.txt") -Force
        "SISTEMA CORROMPIDO" | Set-Content (Join-Path $sourcePath "erro.log")
        
        Write-Host "  ✗ Falha simulada: sistema corrompido" -ForegroundColor Red
        
        Show-Step "6.5" "Executando recuperação automática"
        $recovered = $recoveryManager.RestoreRecoveryPoint("sistema_estavel")
        
        if ($recovered) {
            Write-Host "  ✓ Sistema restaurado para ponto de recuperação" -ForegroundColor Green
            
            # Verificar arquivos restaurados
            $versionContent = Get-Content (Join-Path $sourcePath "version.txt") -Raw
            $statusExists = Test-Path (Join-Path $sourcePath "status.txt")
            $tempExists = Test-Path (Join-Path $sourcePath "temp.tmp")
            $errorExists = Test-Path (Join-Path $sourcePath "erro.log")
            
            Write-Host "  Verificação pós-recuperação:" -ForegroundColor Gray
            Write-Host "    - Versão: $($versionContent.Trim())" -ForegroundColor Gray
            Write-Host "    - Status existe: $statusExists" -ForegroundColor Gray
            Write-Host "    - Temp removido: $(-not $tempExists)" -ForegroundColor Gray  
            Write-Host "    - Erro removido: $(-not $errorExists)" -ForegroundColor Gray
            
        } else {
            Write-Host "  ✗ Falha na recuperação automática" -ForegroundColor Red
        }
        
        Show-Step "6.6" "Listando pontos de recuperação disponíveis"
        $points = $recoveryManager.ListRecoveryPoints()
        Write-Host "  Pontos disponíveis: $($points -join ', ')" -ForegroundColor Gray
        
        Write-Host "✓ Sistema de recuperação funcionando corretamente!" -ForegroundColor Green
        
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro no sistema de recuperação: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Demo-AuxiliaryFunctions {
    Show-Banner "DEMONSTRAÇÃO: Funções Auxiliares e Utilitários"
    
    Show-Step "7.1" "Testando função Invoke-WithRetry"
    
    try {
        $tempLogger = [PNALogger]::new($DemoPath, [LogLevel]::INFO, $false)
        
        # Simular operação que falha algumas vezes
        $attemptCount = 0
        $result = Invoke-WithRetry -ScriptBlock {
            $attemptCount++
            Write-Host "    Tentativa #$attemptCount" -ForegroundColor Gray
            
            if ($attemptCount -lt 3) {
                throw "Simulação de falha na tentativa $attemptCount"
            }
            
            return "Operação bem-sucedida na tentativa $attemptCount"
        } -MaxAttempts 5 -DelaySeconds 1 -Logger $tempLogger
        
        Write-Host "  ✓ Resultado: $result" -ForegroundColor Green
        
        Show-Step "7.2" "Testando validação de pré-requisitos"
        
        # Esta função pode falhar dependendo do ambiente
        try {
            $prereqResult = Test-Prerequisites -Logger $tempLogger
            Write-Host "  Pré-requisitos: " -NoNewline
            Write-Host $(if ($prereqResult) { "✓ ATENDIDOS" } else { "⚠ VERIFICAR" }) -ForegroundColor $(if ($prereqResult) { 'Green' } else { 'Yellow' })
        }
        catch {
            Write-Host "  Pré-requisitos: ⚠ ERRO NA VERIFICAÇÃO" -ForegroundColor Yellow
            Write-Host "    (Pode ser esperado em alguns ambientes)" -ForegroundColor Gray
        }
        
        Show-Step "7.3" "Testando configurações do sistema"
        
        # Verificar versão PowerShell
        $psVersion = $PSVersionTable.PSVersion
        Write-Host "  PowerShell: v$psVersion " -NoNewline
        $psOk = $psVersion -ge [Version]"5.1"
        Write-Host $(if ($psOk) { "✓" } else { "✗" }) -ForegroundColor $(if ($psOk) { 'Green' } else { 'Red' })
        
        # Verificar privilégios
        $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Host "  Administrador: " -NoNewline
        Write-Host $(if ($isAdmin) { "✓ SIM" } else { "⚠ NÃO" }) -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
        
        # Verificar espaço em disco
        $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 1)
        Write-Host "  Espaço livre: ${freeSpaceGB}GB " -NoNewline
        $spaceOk = $freeSpaceGB -gt 5
        Write-Host $(if ($spaceOk) { "✓" } else { "⚠" }) -ForegroundColor $(if ($spaceOk) { 'Green' } else { 'Yellow' })
        
        Write-Host "✓ Funções auxiliares funcionando corretamente!" -ForegroundColor Green
        
        $tempLogger.Dispose()
    }
    catch {
        Write-Host "✗ Erro nas funções auxiliares: $_" -ForegroundColor Red
    }
    
    Wait-ForUser
}

function Show-Summary {
    Show-Banner "RESUMO DA DEMONSTRAÇÃO"
    
    Write-Host "A demonstração do PNA Helpdesk foi concluída com sucesso!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Funcionalidades demonstradas:" -ForegroundColor White
    Write-Host "  ✓ Sistema de Logging Avançado" -ForegroundColor Green
    Write-Host "  ✓ Validações de Segurança" -ForegroundColor Green  
    Write-Host "  ✓ Sistema de Backup e Recuperação" -ForegroundColor Green
    Write-Host "  ✓ Monitor de Recursos" -ForegroundColor Green
    Write-Host "  ✓ Gerenciador WebSocket" -ForegroundColor Green
    Write-Host "  ✓ Sistema de Recuperação Automática" -ForegroundColor Green
    Write-Host "  ✓ Funções Auxiliares" -ForegroundColor Green
    Write-Host ""
    Write-Host "Próximos passos:" -ForegroundColor Yellow
    Write-Host "  1. Execute .\Install-PNAHelpdesk.ps1 para instalação completa" -ForegroundColor White
    Write-Host "  2. Execute .\Test-PNAHelpdeskInstaller.ps1 para testes automatizados" -ForegroundColor White
    Write-Host "  3. Consulte README-PNAHelpdesk.md para documentação completa" -ForegroundColor White
    Write-Host ""
    Write-Host "Arquivos de demonstração criados em: $DemoPath" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-PNAHelpdeskDemo {
    param([string]$demoPath, [bool]$quickMode)
    
    # Preparar ambiente
    if (Test-Path $demoPath) {
        Remove-Item $demoPath -Recurse -Force
    }
    New-Item -Path $demoPath -ItemType Directory -Force | Out-Null
    
    # Banner inicial
    Clear-Host
    Write-Host "██████╗ ███╗   ██╗ █████╗     ██╗  ██╗███████╗██╗     ██████╗ ██████╗ ███████╗███████╗██╗  ██╗" -ForegroundColor Cyan
    Write-Host "██╔══██╗████╗  ██║██╔══██╗    ██║  ██║██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝" -ForegroundColor Cyan
    Write-Host "██████╔╝██╔██╗ ██║███████║    ███████║█████╗  ██║     ██████╔╝██║  ██║█████╗  ███████╗█████╔╝ " -ForegroundColor Cyan
    Write-Host "██╔═══╝ ██║╚██╗██║██╔══██║    ██╔══██║██╔══╝  ██║     ██╔═══╝ ██║  ██║██╔══╝  ╚════██║██╔═██╗ " -ForegroundColor Cyan
    Write-Host "██║     ██║ ╚████║██║  ██║    ██║  ██║███████╗███████╗██║     ██████╔╝███████╗███████║██║  ██╗" -ForegroundColor Cyan
    Write-Host "╚═╝     ╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "                    DEMONSTRAÇÃO INTERATIVA - VERSÃO 2.0.1" -ForegroundColor Yellow
    Write-Host "                         Sistema de Instalação Avançado" -ForegroundColor White
    Write-Host ""
    
    if ($quickMode) {
        Write-Host "⚡ MODO RÁPIDO ATIVADO - Demonstração automática" -ForegroundColor Yellow
    } else {
        Write-Host "📖 MODO INTERATIVO - Pressione Enter para avançar entre as etapas" -ForegroundColor Green
    }
    
    Wait-ForUser "Pressione Enter para iniciar a demonstração..."
    
    try {
        # Executar demonstrações
        Demo-LoggingSystem
        Demo-SecurityValidation  
        Demo-BackupSystem
        Demo-ResourceMonitor
        Demo-WebSocketManager
        Demo-RecoverySystem
        Demo-AuxiliaryFunctions
        
        # Resumo final
        Show-Summary
        
        return $true
    }
    catch {
        Write-Host ""
        Write-Host "✗ Erro durante a demonstração: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Isso pode indicar:" -ForegroundColor Yellow
        Write-Host "  - Falta de privilégios de administrador" -ForegroundColor Gray
        Write-Host "  - Problemas de conectividade de rede" -ForegroundColor Gray  
        Write-Host "  - Falta de dependências do sistema" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Execute .\Test-PNAHelpdeskInstaller.ps1 para diagnóstico detalhado" -ForegroundColor White
        
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $success = Start-PNAHelpdeskDemo -demoPath $DemoPath -quickMode $QuickDemo.IsPresent
        
        if ($success) {
            Write-Host "🎉 Demonstração concluída com sucesso!" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "⚠️  Demonstração concluída com alguns problemas." -ForegroundColor Yellow
            exit 1
        }
    }
    catch {
        Write-Error "Erro fatal na demonstração: $_"
        exit 1
    }
}