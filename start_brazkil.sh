#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Comando stop: encerra todos os serviços Python do BraZKIL
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "stop" ]]; then
    echo "[BraZKIL] Encerrando serviços Python..."
    pkill -f "uvicorn issuer.main"           2>/dev/null || true
    pkill -f "uvicorn verifier.main"         2>/dev/null || true
    pkill -f "uvicorn vdr.main"              2>/dev/null || true
    pkill -f "uvicorn validator_datavalid.main" 2>/dev/null || true
    echo "[BraZKIL] Serviços Python encerrados."
    exit 0
fi

# Mata processos Python anteriores para evitar conflito de porta
pkill -f "uvicorn issuer.main"           2>/dev/null || true
pkill -f "uvicorn verifier.main"         2>/dev/null || true
pkill -f "uvicorn vdr.main"              2>/dev/null || true
pkill -f "uvicorn validator_datavalid.main" 2>/dev/null || true
sleep 1  # aguarda portas serem liberadas

SERVICES=(
	"VDR|http://127.0.0.1:8001/health|/tmp/brazkil-vdr.log"
	"Validator|http://127.0.0.1:8000/health|/tmp/brazkil-validator.log"
	"Issuer|http://127.0.0.1:8002/health|/tmp/brazkil-issuer.log"
	"Verifier|http://127.0.0.1:8003/health|/tmp/brazkil-verifier.log"
)

wait_for_service() {
	local name="$1"
	local url="$2"
	local log_file="$3"
	local attempt=1
	local max_attempts=30

	echo -n "Verificando $name"
	while (( attempt <= max_attempts )); do
		if curl -fsS "$url" >/dev/null 2>&1; then
			echo " - ONLINE"
			return 0
		fi
		echo -n "."
		sleep 1
		((attempt++))
	done

	echo
	echo "ERRO: $name não respondeu em $url"
	echo "Últimas linhas de $log_file:"
	tail -n 20 "$log_file" || true
	return 1
}

echo "============================================================"
echo "  BraZKIL - Iniciando PoC completa"
echo "============================================================"

echo "[1/5] Iniciando VDR (porta 8001)"
python -m uvicorn vdr.main:app --host 0.0.0.0 --port 8001 --reload >/tmp/brazkil-vdr.log 2>&1 &

echo "[2/5] Iniciando Validator Datavalid (porta 8000)"
python -m uvicorn validator_datavalid.main:app --host 0.0.0.0 --port 8000 --reload >/tmp/brazkil-validator.log 2>&1 &

echo "[3/5] Iniciando Issuer (porta 8002)"
# ISSUER_BASE_URL usa o IP do gateway Docker (172.17.0.1) para que:
#   - O wallet walt.id (Docker) consiga chamar de volta o Issuer no host
#   - O browser do usuário também consiga acessar (172.17.0.1 é uma interface local)
# Detecta o gateway da rede docker-compose (tipicamente 172.19.0.1)
# Essa rede é usada pelos containers walt.id e é acessível pelo host
DOCKER_NET="docker-compose_default"
DOCKER_GW=$(docker network inspect "${DOCKER_NET}" --format='{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || \
            docker network inspect bridge --format='{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || \
            echo "127.0.0.1")
export ISSUER_BASE_URL="http://${DOCKER_GW}:8002"
export VERIFIER_BASE_URL="http://${DOCKER_GW}:8003"
echo "  -> ISSUER_BASE_URL=${ISSUER_BASE_URL}"

# Garante que iptables permite tráfego Docker → host nas portas BraZKIL
DOCKER_IF=$(ip link show | grep -oP "(?<=\d: )br-[a-f0-9]+" | head -1)
if [[ -n "$DOCKER_IF" ]]; then
    sudo iptables -C INPUT -i "${DOCKER_IF}" -p tcp --dport 8000:8003 -j ACCEPT 2>/dev/null || \
    sudo iptables -I INPUT -i "${DOCKER_IF}" -p tcp --dport 8000:8003 -j ACCEPT 2>/dev/null || true
    echo "  -> Regra iptables verificada para interface ${DOCKER_IF}"
fi
python -m uvicorn issuer.main:app --host 0.0.0.0 --port 8002 --reload >/tmp/brazkil-issuer.log 2>&1 &

echo "[4/5] Iniciando Verifier (porta 8003)"
python -m uvicorn verifier.main:app --host 0.0.0.0 --port 8003 --reload >/tmp/brazkil-verifier.log 2>&1 &

echo "[5/5] Iniciando wallet walt.id"
cd "$ROOT_DIR/wallet/waltid-identity/docker-compose"
if ! docker compose up -d; then
    echo "[AVISO] Falha ao iniciar Docker. A interface da carteira (7101) não estará disponível."
else
    echo "[OK] Docker iniciado com sucesso."
fi

echo
echo "Aguardando e validando status dos serviços BraZKIL..."
for service in "${SERVICES[@]}"; do
	IFS='|' read -r name url log_file <<< "$service"
	wait_for_service "$name" "$url" "$log_file"
done

echo
echo "Serviços iniciados. Logs dos serviços Python em:"
echo "  /tmp/brazkil-vdr.log"
echo "  /tmp/brazkil-validator.log"
echo "  /tmp/brazkil-issuer.log"
echo "  /tmp/brazkil-verifier.log"
echo
echo "Endpoints esperados:"
echo "  VDR      -> http://127.0.0.1:8001"
echo "  Validator-> http://127.0.0.1:8000"
echo "  Issuer   -> http://127.0.0.1:8002"
echo "  Verifier -> http://127.0.0.1:8003"