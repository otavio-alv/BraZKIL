#!/usr/bin/env bash
# =============================================================================
# BraZKIL — Script de Inicialização Completa da PoC
# Sobe todos os 4 serviços em terminais/subshells separados.
#
# Uso:
#   chmod +x start_brazkil.sh
#   ./start_brazkil.sh
#
# Para parar tudo: ./start_brazkil.sh stop
# =============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$PROJECT_DIR/.logs"
mkdir -p "$LOG_DIR"

stop_all() {
    echo "🛑 Parando todos os serviços BraZKIL..."
    pkill -f "uvicorn vdr.main" 2>/dev/null && echo "  ✅ VDR parado" || echo "  (VDR não estava rodando)"
    pkill -f "uvicorn validator_datavalid.main" 2>/dev/null && echo "  ✅ Validator parado" || echo "  (Validator não estava rodando)"
    pkill -f "uvicorn issuer.main" 2>/dev/null && echo "  ✅ Issuer parado" || echo "  (Issuer não estava rodando)"
    pkill -f "uvicorn verifier.main" 2>/dev/null && echo "  ✅ Verifier parado" || echo "  (Verifier não estava rodando)"
    echo "✅ Todos os serviços parados."
    exit 0
}

if [[ "$1" == "stop" ]]; then stop_all; fi

echo "============================================================"
echo "  🍷 BraZKIL — Iniciando Prova de Conceito Completa"
echo "============================================================"
echo ""

cd "$PROJECT_DIR"

# Verificar se as portas já estão em uso
for port in 8000 8001 8002 8003; do
    if ss -tlnp 2>/dev/null | grep -q ":$port " || lsof -i ":$port" -t 2>/dev/null | grep -q .; then
        echo "⚠️  Porta $port já está em uso. Parando processo existente..."
        pkill -f ":$port" 2>/dev/null || true
        sleep 1
    fi
done

echo "🏛️  [1/4] Iniciando VDR (Trust Registry)        → http://127.0.0.1:8001"
python -m uvicorn vdr.main:app --port 8001 --log-level warning \
    > "$LOG_DIR/vdr.log" 2>&1 &
VDR_PID=$!

echo "🔍 [2/4] Iniciando Validator Datavalid           → http://127.0.0.1:8000"
python -m uvicorn validator_datavalid.main:app --port 8000 --log-level warning \
    > "$LOG_DIR/validator.log" 2>&1 &
VALIDATOR_PID=$!

echo "📋 [3/4] Iniciando Issuer (Middleware OID4VCI)   → http://127.0.0.1:8002"
python -m uvicorn issuer.main:app --port 8002 --log-level warning \
    > "$LOG_DIR/issuer.log" 2>&1 &
ISSUER_PID=$!

echo "🍷 [4/4] Iniciando Verifier (Loja de Vinhos)    → http://127.0.0.1:8003"
python -m uvicorn verifier.main:app --port 8003 --log-level warning \
    > "$LOG_DIR/verifier.log" 2>&1 &
VERIFIER_PID=$!

echo ""
echo "⏳ Aguardando serviços iniciarem..."
sleep 4

# Health checks
echo ""
echo "============================================================"
echo "  Status dos Serviços:"
echo "============================================================"

for name_port in "VDR:8001/health" "Validator:8000/health" "Issuer:8002/health" "Verifier:8003/health"; do
    name="${name_port%%:*}"
    endpoint="${name_port#*:}"
    url="http://127.0.0.1:$endpoint"
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "ERR")
    if [[ "$http_code" == "200" ]]; then
        echo "  ✅ $name está ONLINE ($url)"
    else
        echo "  ❌ $name está OFFLINE (HTTP $http_code) — verifique .logs/$( echo $name | tr '[:upper:]' '[:lower:]').log"
    fi
done

echo ""
echo "============================================================"
echo "  🌐 Loja de Vinhos:  http://127.0.0.1:8003"
echo "  📚 Issuer Docs:     http://127.0.0.1:8002/docs"
echo "  🏛️  VDR Docs:        http://127.0.0.1:8001/docs"
echo "  📋 Verifier Docs:   http://127.0.0.1:8003/docs"
echo ""
echo "  🧪 Teste Rápido (simulação end-to-end):"
echo "     curl -s -X POST 'http://127.0.0.1:8003/verifier/simulate' | python -m json.tool"
echo "============================================================"
echo ""
echo "PIDs: VDR=$VDR_PID  Validator=$VALIDATOR_PID  Issuer=$ISSUER_PID  Verifier=$VERIFIER_PID"
echo "Logs em: $LOG_DIR/"
echo ""
echo "Para parar tudo: ./start_brazkil.sh stop"
echo ""

# Manter o script vivo (opcional — comentar se preferir rodar em background puro)
wait
