"""
    Política de Aceitação do Issuer BraZKIL
    Avalia se os resultados do Datavalid autorizam a emissão da SD-JWT VC.
"""

from dataclasses import dataclass
from datetime import date


# Limiar mínimo de similaridade de nome aceito pelo Issuer
NAME_SIMILARITY_THRESHOLD = 0.80


@dataclass
class PolicyDecision:
    """Resultado da avaliação da política de aceitação do Issuer."""
    approved: bool
    age_over_18: bool
    reason: str


def evaluate_issuance_policy(
    rfb_exists: bool,
    cpf_regular: bool,
    name_similarity: float,
    birth_date_valid: bool,
    birth_date: date,
) -> PolicyDecision:
    """
    Avalia a política de aceitação BraZKIL para emissão da SD-JWT VC.

    Critérios obrigatórios (todos devem ser satisfeitos):
      1. rfb_exists       — CPF encontrado na Receita Federal
      2. cpf_regular      — CPF com situação REGULAR na Receita Federal
      3. name_similarity  — Similaridade do nome >= NAME_SIMILARITY_THRESHOLD
      4. birth_date_valid — Data de nascimento validada na Receita Federal
      5. age_over_18      — Idade calculada a partir da data de nascimento >= 18 anos

    Retorna:
      PolicyDecision com approved=True e age_over_18=True se todos os critérios
      forem atendidos, ou approved=False com a razão da rejeição.
    """

    # 1. CPF encontrado na RFB
    if not rfb_exists:
        return PolicyDecision(
            approved=False,
            age_over_18=False,
            reason="CPF não encontrado na Receita Federal Brasileira."
        )

    # 2. CPF com situação REGULAR
    if not cpf_regular:
        return PolicyDecision(
            approved=False,
            age_over_18=False,
            reason="CPF não está em situação REGULAR na Receita Federal."
        )

    # 3. Similaridade do nome acima do limiar
    if name_similarity < NAME_SIMILARITY_THRESHOLD:
        return PolicyDecision(
            approved=False,
            age_over_18=False,
            reason=f"Similaridade do nome ({name_similarity:.2f}) abaixo do limiar mínimo ({NAME_SIMILARITY_THRESHOLD})."
        )

    # 4. Data de nascimento validada na Receita Federal
    if not birth_date_valid:
        return PolicyDecision(
            approved=False,
            age_over_18=False,
            reason="Data de nascimento não confirmada pela Receita Federal."
        )

    # 5. Calcular se o titular tem 18 anos ou mais na data atual
    today = date.today()
    age = today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )
    age_over_18 = age >= 18

    if not age_over_18:
        return PolicyDecision(
            approved=False,
            age_over_18=False,
            reason=f"Titular tem {age} anos — maioridade (18) não atingida."
        )

    return PolicyDecision(
        approved=True,
        age_over_18=True,
        reason=f"Todos os critérios atendidos. Titular tem {age} anos."
    )
