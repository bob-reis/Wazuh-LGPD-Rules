# LGPD Compliance — Wazuh

Mapeamento das regras nativas do Wazuh para a **Lei Geral de Proteção de Dados (Lei 13.709/2018)**, gerado a partir dos mapeamentos GDPR já presentes no ruleset padrão.

## Conteúdo

| Arquivo | Descrição |
|---|---|
| `generate_lgpd_rules.py` | Script que lê as regras nativas e gera os overrides com tags LGPD |
| `local_rules_lgpd.xml` | Arquivo de regras gerado — pronto para deploy |

## Mapeamento GDPR → LGPD

O Wazuh usa nativamente 4 artigos GDPR. Cada um tem correspondente direto na LGPD:

| Tag Wazuh (GDPR) | Artigo GDPR | Tag LGPD | Artigo LGPD | Regras |
|---|---|---|---|---|
| `gdpr_II_5.1.f` | Art. 5(1)(f) — Integridade e confidencialidade | `lgpd_Art6_VII` | Art. 6, VII — Princípio da segurança | 40 |
| `gdpr_IV_30.1.g` | Art. 30(1)(g) — Registro de atividades de tratamento | `lgpd_Art37` | Art. 37 — Registro das operações de tratamento | 49 |
| `gdpr_IV_32.2` | Art. 32(2) — Segurança no tratamento | `lgpd_Art46` | Art. 46 — Medidas de segurança técnicas e administrativas | 541 |
| `gdpr_IV_35.7.d` | Art. 35(7)(d) — DPIA | `lgpd_Art38` | Art. 38 — RIPD (Relatório de Impacto) | 1186 |

**Total: 1353 regras com mapeamento LGPD** em 114 arquivos do ruleset nativo (Wazuh 4.14.5).

## Como implementar em outro ambiente

### Pré-requisitos

- Wazuh Manager instalado (testado na versão 4.x)
- Python 3.8+ no host (apenas para regerar o arquivo)
- Acesso ao diretório de regras do usuário: `/var/ossec/etc/rules/`

### Opção A — Deploy direto do arquivo gerado (mais rápido)

Use quando o `local_rules_lgpd.xml` já foi gerado para a sua versão do Wazuh.

```bash
# 1. Copiar o arquivo para o diretório de regras customizadas
cp local_rules_lgpd.xml /var/ossec/etc/rules/

# 2. Validar a configuração (sem reiniciar)
/var/ossec/bin/wazuh-analysisd -t

# 3. Se não houver erros CRITICAL, reiniciar o manager
systemctl restart wazuh-manager
# ou, em Docker:
docker restart <nome-do-container-wazuh-manager>

# 4. Verificar que as regras foram carregadas
grep -i "lgpd\|local_rules_lgpd" /var/ossec/logs/ossec.log
```

> **Atenção:** O arquivo `local_rules_lgpd.xml` deste repositório foi gerado para o Wazuh 4.14.5.
> Se você estiver em uma versão diferente, regenere-o conforme a Opção B.

### Opção B — Regenerar para outra versão do Wazuh

Use quando sua versão do Wazuh for diferente da que gerou o arquivo atual.

```bash
# 1. Instalar dependências (apenas biblioteca padrão Python, sem extras)
python3 --version  # requer 3.8+

# 2. Gerar o arquivo para a instalação atual
python3 generate_lgpd_rules.py \
    --rules-dir /var/ossec/ruleset/rules \
    --output    /var/ossec/etc/rules/local_rules_lgpd.xml

# Parâmetros opcionais:
#   --min-level 5          → incluir somente regras de nível >= 5
#   --exclude-files 0215-policy_rules.xml 0outro.xml  → excluir arquivos adicionais

# 3. Validar e aplicar (mesmo que Opção A, passos 2-4)
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

### Opção C — Deploy em Docker com volume montado

Para ambientes onde as regras do usuário são em volume Docker.

```bash
# Supondo que o volume do Wazuh está em:
# /opt/wazuh-docker/volumes/wazuh_etc/_data/rules/

cp local_rules_lgpd.xml /opt/wazuh-docker/volumes/wazuh_etc/_data/rules/

# Validar dentro do container
docker exec <wazuh-manager> /var/ossec/bin/wazuh-analysisd -t

# Reiniciar
docker restart <wazuh-manager>
```

## Verificação pós-deploy

### Via API REST do Wazuh

```bash
# Obter token
TOKEN=$(curl -s -k -u "wazuh-wui:<senha>" \
    -X GET "https://localhost:55000/security/user/authenticate?raw=true")

# Verificar se a regra 5710 (SSH brute force) tem tags LGPD
curl -s -k -H "Authorization: Bearer $TOKEN" \
    "https://localhost:55000/rules?rule_ids=5710" | \
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d['data']['affected_items']:
    lgpd=[g for g in r.get('groups',[]) if 'lgpd' in g]
    print(f'Rule {r[\"id\"]}: LGPD={lgpd}, file={r[\"filename\"]}')
"
# Saída esperada:
# Rule 5710: LGPD=['lgpd_Art46', 'lgpd_Art38', 'lgpd'], file=local_rules_lgpd.xml
```

### Via dashboard OpenSearch/Kibana

Para filtrar alertas por conformidade LGPD no dashboard:

1. Abra o Wazuh Dashboard → **Security Events**
2. Adicione o filtro: `rule.groups: lgpd_Art46` (ou qualquer outro artigo)
3. Para uma visão consolidada, use: `rule.groups: lgpd_*`

### Criar um índice de padrão para compliance LGPD

No OpenSearch Dashboards (Dev Tools):

```json
GET wazuh-alerts-*/_search
{
  "query": {
    "terms": {
      "rule.groups": ["lgpd_Art38", "lgpd_Art46", "lgpd_Art37", "lgpd_Art6_VII"]
    }
  },
  "aggs": {
    "por_artigo": {
      "terms": { "field": "rule.groups", "include": "lgpd_.*" }
    }
  }
}
```

## Como funciona tecnicamente

O Wazuh permite sobrescrever regras nativas usando `overwrite="yes"` em arquivos dentro de `etc/rules/`. O script lê cada regra original, copia todos os seus atributos e elementos, e adiciona as tags LGPD correspondentes ao elemento `<group>`:

```xml
<!-- Regra original (ruleset/rules/0030-ssh_rules.xml) -->
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user</description>
  <group>authentication_failed,pci_dss_10.2.4,gdpr_IV_35.7.d,gdpr_IV_32.2,...</group>
</rule>

<!-- Override gerado (etc/rules/local_rules_lgpd.xml) -->
<rule id="5710" level="5" overwrite="yes">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user</description>
  <group>authentication_failed,pci_dss_10.2.4,gdpr_IV_35.7.d,gdpr_IV_32.2,...,lgpd_Art46,lgpd_Art38,</group>
</rule>
```

As tags GDPR **não são removidas** — o override acrescenta as LGPD ao conjunto existente.

## Avisos e limitações

- **Regenerar após atualizações do Wazuh**: ao atualizar o Wazuh Manager, as regras nativas podem mudar. Execute o script novamente e substitua o arquivo.
- **`0215-policy_rules.xml`**: este arquivo está na lista `rule_exclude` do `ossec.conf` padrão do Wazuh. O script o exclui automaticamente para evitar warnings.
- **`0910-ms-exchange-proxylogon_rules.xml`**: contém XML malformado (token inválido). O script o ignora com aviso — as regras deste arquivo não recebem tags LGPD.
- **Warnings `if_group`**: Wazuh não permite sobrescrever o atributo `if_group` via overrides. Estes warnings são esperados e não afetam a funcionalidade — as tags LGPD são aplicadas corretamente.
- **Escopo**: apenas regras com pelo menos uma tag GDPR recebem override LGPD. Regras sem mapeamento GDPR não são alteradas.
