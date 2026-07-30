# Скрипт для быстрого запуска сид-ноды Primus (Windows)

# 1. Задаем порт
$env:PRIMUS_PORT = if ($args.Length -gt 0) { $args[0] } else { "9000" }

# 2. Включаем логирование
$env:RUST_LOG = "info"

# 3. Устанавливаем папку для ключей рядом со скриптом
$env:PRIMUS_CONFIG_DIR = ".\primus-seed-data"

# Проверяем и создаем папку, если ее нет
if (-Not (Test-Path -Path $env:PRIMUS_CONFIG_DIR)) {
    New-Item -ItemType Directory -Path $env:PRIMUS_CONFIG_DIR | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Запуск сид-ноды Primus..." -ForegroundColor Green
Write-Host "📡 Порт: $env:PRIMUS_PORT (убедитесь, что UDP открыт в брандмауэре)" -ForegroundColor Yellow
Write-Host "📁 Данные сохраняются в: $env:PRIMUS_CONFIG_DIR" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 4. Запуск
cargo run --release --bin messenger
