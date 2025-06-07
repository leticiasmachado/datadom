# Dataset Automation Tool for Analysis of Domains - DATADOM

Ferramenta desenvolvida para o TCC em Ciência da Computação que gera conjuntos de dados para treinamento de modelos de ML na detecção de domínios maliciosos.

## 🔍 Visão Geral

Solução Python que:
- Coleta domínios de listas de bloqueio (maliciosos) e permissão (legítimos)
- Padroniza e enriquece os dados com características relevantes
- Gera datasets balanceados para modelos de ML
- Oferece processamento paralelo com capacidade de interrupção e retomada segura

## ⚙️ Funcionamento

### Fluxo Principal

1. **Validação Inicial**  
   - Carrega e valida o arquivo `configs.json` usando JSON Schema  
   - Se inválido: exibe mensagem de erro e encerra  
   - Se válido: verifica a existência de `input.csv`

2. **Controle de Continuidade**  
   - Se `input.csv` **não existe**:  
     - Identifica as fontes de dados ativas no `configs.json`  
     - Coleta domínios das listas selecionadas  
     - Salva os dados brutos em `input.csv` (com coluna `"OK"` para rastreamento)  
   - Se `input.csv` **existe**:  
     - Pergunta ao usuário se deseja continuar o processamento anterior  
     - Se **não**: recria o arquivo do zero  
     - Se **sim**: remove apenas os domínios já processados (marcados como `"OK" = True`)

3. **Processamento Paralelo**  
   - Divide os domínios em *chunks* conforme número de threads definido  
   - Cada thread executa:  
     - Extração de características selecionadas pelo usuário (ex: comprimento do domínio, TLD, etc)  
     - Verificação em listas de bloqueio/permissão  
     - Atualização do status no `input.csv`  

4. **Consolidação Final**  
   - Agrega todos os resultados processados  
   - Gera o arquivo `output.csv` com:  
     - Domínios
     - Features extraídas 
     - Classificação (malicioso/legítimo)  
   - Mantém metade do dataset para cada classe (balanceamento automático)

5. **Recuperação de Falhas**  
   - Interrupção segura via tecla `ENTER`  
   - Estado salvo em `input.csv` permite retomar exatamente do ponto parado  

![Fluxograma da Ferramenta](link_para_o_fluxograma_no_github)

### Fontes de Dados
| Tipo           | Fontes Incluídas                                                                 |
|----------------|----------------------------------------------------------------------------------|
| **Permissão**  | Majestic Million, Cisco Umbrella                                                 |
| **Bloqueio de domínios**   | Abuse.ch, Bambenek (domínios/IPs), Hagezi, OpenPhish, PhishTank, UrlAbuse        |
| **Bloqueio de IPs**        | Blocklist.de, Bambenek (DGA)                                                     |

## 🛠 Configuração

Edite o arquivo `configs.json` para selecionar:
- Fontes de dados desejadas
- Número de domínios final (metade será malicioso e a outra metade legítimo)
- Número de threads para processamento paralelo
- Features a serem incluídas

## 📊 Processamento de Dados

### Etapas Principais:
1. **Padronização**:
   - Extração limpa de domínios (remoção de HTTP/HTTPS, ports)
   - Unificação de formatos

2. **Deduplicação**:
   - Remoção automática de entradas duplicadas
   - Preservação de metadados relevantes

3. **Processamento Paralelo**:
   - Divisão em chunks por thread
   - Mecanismo de pause/resume (tecla ENTER)

## 📁 Estrutura de Arquivos

```
datadom/
├── data/                    # Dados das fontes
├── domain_checkers/         # Verificadores de listas
├── downloads/               # Gerenciamento de downloads
├── features_processor/      # Processamento de características
├── json_processor/          # Validação de JSON Schema
├── utils/                   # Utilitários compartilhados
├── dataset_processor.py     # Processamento principal
├── features.txt             # Lista de features disponíveis
└── main.py                  # Ponto de entrada
```

## 🚀 Como Usar
1. Clone o repositório:
   ```bash
   git clone https://github.com/leticiasmachado/datadom.git
   ```
2. Configure o `configs.json`
3. Execute o módulo principal:
   ```bash
   python main.py
   ```
4. Para retomar processamento interrompido, mantenha o `input.csv` e execute novamente

## ✨ Features Técnicas
- **Validação Robusta**: JSON Schema para configurações
- **Modular**: Facilidade para adicionar novas fontes
- **Resiliente**: Processamento recuperável após interrupções
- **Escalável**: Paralelização via threads

## 📌 Próximos Passos
- [ ] Adicionar mais fontes de dados (Domain Rankins para lista de permissão, SANS Internet Storm Center para lista de bloqueio)
- [ ] Inclusão de métricas de TTL (time-to-live)
- [ ] Explorar alterativas para a biblioteca Whois
- [ ] Implementação de cache para consultas repetitivas
