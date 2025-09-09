<#
.SYNOPSIS
    Script de teste para validar o instalador do PNA Helpdesk

.DESCRIPTION
    Este script executa uma bateria de testes para validar todas as funcionalidades
    implementadas no instalador do PNA Helpdesk, incluindo:
    - Sistema de logging
    - Validações de segurança
    - Sistema de backup e recuperação
    - Monitoramento de recursos
    - Gerenciamento de WebSocket
    - Tratamento de erros

.EXAMPLE
    .\Test-PNAHelpdeskInstaller.ps1 -Verbose

.NOTES
    Autor: PNA Development Team
    Versão: 1.0
    Data: 2024
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TestPath = "C:\Temp\PNAHelpdeskTest"
)

#Requires -Version 5.1

# ============================================================================
# CONFIGURAÇÕES DE TESTE
# ============================================================================

$ErrorActionPreference = "Continue"
$VerbosePreference = if ($PSBoundParameters.ContainsKey('Verbose')) { 'Continue' } else { 'SilentlyContinue' }

# Importar as classes do instalador principal
$installerPath = Join-Path $PSScriptRoot "Install-PNAHelpdesk.ps1"
if (-not (Test-Path $installerPath)) {
    Write-Error "Arquivo do instalador não encontrado: $installerPath"
    exit 1
}

# Carregar o instalador como módulo
. $installerPath

# ============================================================================
# FRAMEWORK DE TESTE
# ============================================================================

class TestResult {
    [string]$TestName
    [bool]$Passed
    [string]$Message
    [datetime]$Timestamp
    [hashtable]$Details
    
    TestResult([string]$name, [bool]$passed, [string]$message, [hashtable]$details = @{}) {
        $this.TestName = $name
        $this.Passed = $passed
        $this.Message = $message
        $this.Timestamp = Get-Date
        $this.Details = $details
    }
}

class TestRunner {
    [System.Collections.ArrayList]$Results
    [PNALogger]$Logger
    [int]$TotalTests
    [int]$PassedTests
    [int]$FailedTests
    
    TestRunner([PNALogger]$logger) {
        $this.Results = @()
        $this.Logger = $logger
        $this.TotalTests = 0
        $this.PassedTests = 0
        $this.FailedTests = 0
    }
    
    [TestResult] RunTest([string]$testName, [scriptblock]$testScript) {
        $this.TotalTests++
        $this.Logger.Info("Executando teste: $testName")
        
        try {
            $result = & $testScript
            $testResult = [TestResult]::new($testName, $true, "Teste passou com sucesso", @{})
            $this.PassedTests++
            $this.Logger.Info("✓ PASSOU: $testName")
        }
        catch {
            $testResult = [TestResult]::new($testName, $false, "Teste falhou: $_", @{'Exception' = $_.Exception})
            $this.FailedTests++
            $this.Logger.Error("✗ FALHOU: $testName - $_")
        }
        
        $this.Results.Add($testResult) | Out-Null
        return $testResult
    }
    
    [void] PrintSummary() {
        Write-Host "`n=== RESUMO DOS TESTES ===" -ForegroundColor Cyan
        Write-Host "Total de testes: $($this.TotalTests)" -ForegroundColor White
        Write-Host "Passou: $($this.PassedTests)" -ForegroundColor Green
        Write-Host "Falhou: $($this.FailedTests)" -ForegroundColor Red
        
        $successRate = if ($this.TotalTests -gt 0) { [math]::Round(($this.PassedTests / $this.TotalTests) * 100, 2) } else { 0 }
        Write-Host "Taxa de sucesso: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { 'Green' } else { 'Yellow' })
        
        if ($this.FailedTests -gt 0) {
            Write-Host "`nTestes falhados:" -ForegroundColor Red
            foreach ($result in $this.Results) {
                if (-not $result.Passed) {
                    Write-Host "  - $($result.TestName): $($result.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

# ============================================================================
# TESTES DO SISTEMA DE LOGGING
# ============================================================================

function Test-LoggingSystem {
    param([string]$testPath)
    
    Write-Verbose "Testando sistema de logging..."
    
    # Criar diretório de teste
    $logPath = Join-Path $testPath "Logs"
    if (Test-Path $logPath) { Remove-Item $logPath -Recurse -Force }
    
    # Teste 1: Inicialização do logger
    $logger = [PNALogger]::new($logPath, [LogLevel]::DEBUG, $false)
    if (-not (Test-Path $logger.LogFile)) {
        throw "Arquivo de log não foi criado"
    }
    
    # Teste 2: Diferentes níveis de log
    $logger.Debug("Mensagem de debug")
    $logger.Info("Mensagem de info")
    $logger.Warning("Mensagem de warning")
    $logger.Error("Mensagem de erro")
    $logger.Critical("Mensagem crítica")
    
    # Teste 3: Log com contexto
    $logger.Info("Teste com contexto", @{
        'Usuario' = 'TestUser'
        'Operacao' = 'TestOperation'
        'Dados' = @{ 'Key' = 'Value' }
    })
    
    # Verificar conteúdo do arquivo
    $logContent = Get-Content $logger.LogFile -Raw
    if ($logContent -notmatch "Mensagem de debug|Mensagem de info|Mensagem de warning|Mensagem de erro|Mensagem crítica") {
        throw "Conteúdo do log não contém as mensagens esperadas"
    }
    
    $logger.Dispose()
    return $true
}

# ============================================================================
# TESTES DE VALIDAÇÃO DE SEGURANÇA
# ============================================================================

function Test-SecurityValidation {
    param([PNALogger]$logger)
    
    Write-Verbose "Testando validações de segurança..."
    
    $validator = [SecurityValidator]::new($logger)
    
    # Teste 1: Validação de token - casos válidos
    $validToken = "abcdef1234567890abcdef1234567890abcdef12"
    if (-not $validator.ValidateToken($validToken)) {
        throw "Token válido foi rejeitado"
    }
    
    # Teste 2: Validação de token - casos inválidos
    $invalidTokens = @(
        "",                    # Vazio
        "123",                # Muito curto
        "example",            # Token proibido
        "test123456789",      # Token proibido
        "valid<script>alert('xss')</script>token"  # Caracteres perigosos
    )
    
    foreach ($invalidToken in $invalidTokens) {
        if ($validator.ValidateToken($invalidToken)) {
            throw "Token inválido foi aceito: $invalidToken"
        }
    }
    
    # Teste 3: Validação de credenciais
    $validCred = New-Object System.Management.Automation.PSCredential(
        "testuser", 
        (ConvertTo-SecureString "TestPass123!" -AsPlainText -Force)
    )
    
    if (-not $validator.ValidateCredentials($validCred)) {
        throw "Credenciais válidas foram rejeitadas"
    }
    
    # Teste 4: Validação de conectividade (mock)
    # Nota: Este teste pode falhar se não houver conectividade, mas não deve gerar erro
    try {
        $result = $validator.ValidateNetworkConnection("https://www.google.com", 5)
        # Resultado pode ser true ou false dependendo da conectividade
    }
    catch {
        # Falha na conectividade não é um erro de teste
    }
    
    return $true
}

# ============================================================================
# TESTES DO SISTEMA DE BACKUP
# ============================================================================

function Test-BackupSystem {
    param([string]$testPath, [PNALogger]$logger)
    
    Write-Verbose "Testando sistema de backup..."
    
    # Preparar ambiente de teste
    $sourcePath = Join-Path $testPath "SourceData"
    $backupPath = Join-Path $testPath "Backups"
    $restorePath = Join-Path $testPath "RestoreData"
    
    # Limpar diretórios existentes
    @($sourcePath, $backupPath, $restorePath) | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
    
    # Criar dados de teste
    $testFile1 = Join-Path $sourcePath "test1.txt"
    $testFile2 = Join-Path $sourcePath "test2.txt"
    "Conteúdo do arquivo de teste 1" | Set-Content $testFile1
    "Conteúdo do arquivo de teste 2" | Set-Content $testFile2
    
    # Teste 1: Criação de backup
    $backupManager = [BackupManager]::new($backupPath, $logger, 3)
    $backupFilePath = $backupManager.CreateBackup($sourcePath, "test_backup")
    
    if (-not (Test-Path $backupFilePath)) {
        throw "Arquivo de backup não foi criado"
    }
    
    # Teste 2: Restauração de backup
    $success = $backupManager.RestoreBackup($backupFilePath, $restorePath)
    if (-not $success) {
        throw "Falha na restauração do backup"
    }
    
    # Verificar arquivos restaurados
    $restoredFile1 = Join-Path $restorePath "test1.txt"
    $restoredFile2 = Join-Path $restorePath "test2.txt"
    
    if (-not (Test-Path $restoredFile1) -or -not (Test-Path $restoredFile2)) {
        throw "Arquivos não foram restaurados corretamente"
    }
    
    # Verificar conteúdo
    $originalContent1 = Get-Content $testFile1 -Raw
    $restoredContent1 = Get-Content $restoredFile1 -Raw
    
    if ($originalContent1 -ne $restoredContent1) {
        throw "Conteúdo dos arquivos restaurados não confere"
    }
    
    # Teste 3: Limpeza de backups antigos
    # Criar múltiplos backups
    for ($i = 1; $i -le 5; $i++) {
        Start-Sleep -Milliseconds 100  # Garantir timestamps diferentes
        $backupManager.CreateBackup($sourcePath, "cleanup_test")
    }
    
    # Verificar se apenas MaxBackups foram mantidos
    $backups = Get-ChildItem -Path $backupPath -Filter "cleanup_test_*.zip"
    if ($backups.Count -gt $backupManager.MaxBackups) {
        throw "Limpeza de backups antigos não funcionou corretamente"
    }
    
    return $true
}

# ============================================================================
# TESTES DO MONITOR DE RECURSOS
# ============================================================================

function Test-ResourceMonitor {
    param([PNALogger]$logger)
    
    Write-Verbose "Testando monitor de recursos..."
    
    # Teste 1: Inicialização do monitor
    $monitor = [ResourceMonitor]::new($logger)
    
    # Teste 2: Obter métricas atuais
    $usage = $monitor.GetCurrentUsage()
    
    if ($usage.Count -eq 0) {
        throw "Monitor não retornou métricas de uso"
    }
    
    # Verificar se as métricas essenciais estão presentes
    $requiredMetrics = @('CPUUsage', 'AvailableMemoryMB', 'ProcessMemoryMB', 'Timestamp')
    foreach ($metric in $requiredMetrics) {
        if (-not $usage.ContainsKey($metric)) {
            throw "Métrica obrigatória ausente: $metric"
        }
    }
    
    # Teste 3: Verificar valores válidos
    if ($usage.CPUUsage -lt 0 -or $usage.CPUUsage -gt 100) {
        throw "Uso de CPU fora do intervalo válido: $($usage.CPUUsage)"
    }
    
    if ($usage.AvailableMemoryMB -lt 0) {
        throw "Memória disponível inválida: $($usage.AvailableMemoryMB)"
    }
    
    if ($usage.ProcessMemoryMB -lt 0) {
        throw "Memória do processo inválida: $($usage.ProcessMemoryMB)"
    }
    
    # Teste 4: Verificação de restrições (pode ou não estar restrito)
    $isConstrained = $monitor.IsResourceConstraint()
    # Este teste apenas verifica se a função não gera erro
    
    $monitor.Dispose()
    return $true
}

# ============================================================================
# TESTES DO GERENCIADOR WEBSOCKET
# ============================================================================

function Test-WebSocketManager {
    param([PNALogger]$logger)
    
    Write-Verbose "Testando gerenciador WebSocket..."
    
    # Teste 1: Inicialização do WebSocket
    $wsManager = [WebSocketManager]::new("wss://echo.websocket.org", 5000, $logger)
    
    # Teste 2: Tentativa de conexão (pode falhar se não houver conectividade)
    try {
        $connected = $wsManager.Connect()
        
        if ($connected) {
            # Teste 3: Envio de mensagem
            $testMessage = "Mensagem de teste do PNA Helpdesk"
            $sent = $wsManager.SendMessage($testMessage)
            
            if (-not $sent) {
                $logger.Warning("Falha ao enviar mensagem WebSocket")
            }
            
            # Teste 4: Tentativa de receber mensagem
            $received = $wsManager.ReceiveMessage()
            # Pode ou não receber resposta dependendo do servidor
            
            $wsManager.Disconnect()
        } else {
            $logger.Warning("Não foi possível conectar ao WebSocket (esperado em alguns ambientes)")
        }
    }
    catch {
        $logger.Warning("Teste de WebSocket falhou (pode ser esperado sem conectividade): $_")
    }
    
    return $true
}

# ============================================================================
# TESTES DO SISTEMA DE RECUPERAÇÃO
# ============================================================================

function Test-RecoverySystem {
    param([string]$testPath, [PNALogger]$logger)
    
    Write-Verbose "Testando sistema de recuperação..."
    
    # Preparar ambiente
    $sourcePath = Join-Path $testPath "RecoverySource"
    $backupPath = Join-Path $testPath "RecoveryBackups"
    
    if (Test-Path $sourcePath) { Remove-Item $sourcePath -Recurse -Force }
    if (Test-Path $backupPath) { Remove-Item $backupPath -Recurse -Force }
    
    New-Item -Path $sourcePath -ItemType Directory -Force | Out-Null
    "Dados originais" | Set-Content (Join-Path $sourcePath "original.txt")
    
    # Teste 1: Criação do sistema de recuperação
    $backupManager = [BackupManager]::new($backupPath, $logger)
    $recoveryManager = [RecoveryManager]::new($logger, $backupManager)
    
    # Teste 2: Criar ponto de recuperação
    $recoveryManager.CreateRecoveryPoint("test_point", $sourcePath)
    
    # Verificar se o ponto foi criado
    $recoveryPoints = $recoveryManager.ListRecoveryPoints()
    if ($recoveryPoints -notcontains "test_point") {
        throw "Ponto de recuperação não foi criado"
    }
    
    # Teste 3: Modificar dados originais
    "Dados modificados" | Set-Content (Join-Path $sourcePath "modified.txt")
    Remove-Item (Join-Path $sourcePath "original.txt") -Force
    
    # Teste 4: Restaurar ponto de recuperação
    $restored = $recoveryManager.RestoreRecoveryPoint("test_point")
    if (-not $restored) {
        throw "Falha na restauração do ponto de recuperação"
    }
    
    # Verificar se dados foram restaurados
    $originalFile = Join-Path $sourcePath "original.txt"
    $modifiedFile = Join-Path $sourcePath "modified.txt"
    
    if (-not (Test-Path $originalFile)) {
        throw "Arquivo original não foi restaurado"
    }
    
    if (Test-Path $modifiedFile) {
        throw "Arquivo modificado não deveria existir após restauração"
    }
    
    return $true
}

# ============================================================================
# TESTES DE FUNÇÕES AUXILIARES
# ============================================================================

function Test-AuxiliaryFunctions {
    param([PNALogger]$logger)
    
    Write-Verbose "Testando funções auxiliares..."
    
    # Teste 1: Função Invoke-WithRetry
    $attemptCount = 0
    $result = Invoke-WithRetry -ScriptBlock {
        $attemptCount++
        if ($attemptCount -lt 2) {
            throw "Tentativa $attemptCount falhou"
        }
        return "Sucesso na tentativa $attemptCount"
    } -MaxAttempts 3 -DelaySeconds 1 -Logger $logger
    
    if ($result -ne "Sucesso na tentativa 2") {
        throw "Invoke-WithRetry não funcionou corretamente: $result"
    }
    
    # Teste 2: Teste de pré-requisitos (simulação)
    # Esta função pode falhar em ambientes sem privilégios adequados
    try {
        $prereqResult = Test-Prerequisites -Logger $logger
        # Resultado pode ser true ou false dependendo do ambiente
    }
    catch {
        $logger.Warning("Teste de pré-requisitos falhou (pode ser esperado): $_")
    }
    
    return $true
}

# ============================================================================
# FUNÇÃO PRINCIPAL DE TESTE
# ============================================================================

function Start-PNAHelpdeskTests {
    param([string]$testPath)
    
    Write-Host "=== INICIANDO TESTES DO PNA HELPDESK INSTALLER ===" -ForegroundColor Cyan
    
    # Preparar ambiente de teste
    if (Test-Path $testPath) {
        Remove-Item $testPath -Recurse -Force
    }
    New-Item -Path $testPath -ItemType Directory -Force | Out-Null
    
    # Inicializar sistema de teste
    $logPath = Join-Path $testPath "TestLogs"
    $logger = [PNALogger]::new($logPath, [LogLevel]::DEBUG, $true)
    $testRunner = [TestRunner]::new($logger)
    
    try {
        $logger.Info("=== INICIANDO BATERIA DE TESTES ===")
        
        # Executar todos os testes
        $testRunner.RunTest("Sistema de Logging", { Test-LoggingSystem -testPath $testPath })
        $testRunner.RunTest("Validações de Segurança", { Test-SecurityValidation -logger $logger })
        $testRunner.RunTest("Sistema de Backup", { Test-BackupSystem -testPath $testPath -logger $logger })
        $testRunner.RunTest("Monitor de Recursos", { Test-ResourceMonitor -logger $logger })
        $testRunner.RunTest("Gerenciador WebSocket", { Test-WebSocketManager -logger $logger })
        $testRunner.RunTest("Sistema de Recuperação", { Test-RecoverySystem -testPath $testPath -logger $logger })
        $testRunner.RunTest("Funções Auxiliares", { Test-AuxiliaryFunctions -logger $logger })
        
        $logger.Info("=== TESTES CONCLUÍDOS ===")
        
        # Exibir resumo
        $testRunner.PrintSummary()
        
        # Retornar resultado
        return @{
            'Success' = ($testRunner.FailedTests -eq 0)
            'TotalTests' = $testRunner.TotalTests
            'PassedTests' = $testRunner.PassedTests
            'FailedTests' = $testRunner.FailedTests
            'Results' = $testRunner.Results
            'LogFile' = $logger.LogFile
        }
    }
    finally {
        $logger.Dispose()
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Start-PNAHelpdeskTests -testPath $TestPath
        
        if ($result.Success) {
            Write-Host "`n✓ Todos os testes passaram com sucesso!" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "`n✗ Alguns testes falharam. Verifique os detalhes acima." -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Error "Erro fatal durante os testes: $_"
        exit 1
    }
}