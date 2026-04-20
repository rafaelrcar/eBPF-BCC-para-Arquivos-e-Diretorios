# 🐝 Laboratório eBPF/BCC para Arquivos e Diretórios

> Laboratório introdutório de **observabilidade no subsistema de arquivos** usando ferramentas baseadas em **eBPF/BCC**: `filetop`, `dirtop` e `fileslower`.

[![Linux](https://img.shields.io/badge/Linux-required-blue?logo=linux)](https://www.kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-BCC-orange)](https://ebpf.io)
[![Licença](https://img.shields.io/badge/licença-GPL--2.0-green)](LICENSE)

---

## Visão Geral

Este laboratório é um primeiro passo para entender como o eBPF pode ser usado para observar o comportamento do sistema de arquivos sem instrumentação manual de código.

Em vez de escrever um programa eBPF do zero, o foco aqui é usar três ferramentas prontas do pacote BCC:

- `filetop-bpfcc` para identificar os arquivos mais acessados.
- `dirtop-bpfcc` para identificar os diretórios mais ativos.
- `fileslower-bpfcc` para destacar operações de arquivo com maior latência.

O objetivo é responder perguntas simples, mas muito úteis na prática:

- Quais arquivos concentram mais leitura e escrita?
- Quais diretórios viraram hotspots de I/O?
- Quais operações de arquivo estão mais lentas do que o esperado?

Este material é intencionalmente pequeno. Ele serve como base para um laboratório futuro com programas eBPF próprios.

---

## Ambiente do Laboratório

```
┌──────────────────────────────────────────────┐
│                Host Linux                    │
│                                              │
│  Terminal A: gera carga de I/O               │
│  Terminal B: filetop                         │
│  Terminal C: dirtop                          │
│  Terminal D: fileslower                      │
│                                              │
│  Sandbox: /tmp/ebpf-files-lab                │
└──────────────────────────────────────────────┘
```

O laboratório roda no próprio host Linux. Não há topologia de rede nesta primeira versão, porque o foco está no caminho de arquivos e diretórios dentro do kernel.

---

## Pré-requisitos

### 1. Sistema operacional

- Linux com suporte a eBPF.
- Acesso de `sudo`.
- Kernel compatível com ferramentas BCC.

### 2. Instalar dependências

Em distribuições baseadas em Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

Se o pacote de headers do kernel exato não estiver disponível no repositório da sua distribuição, instale a variante correspondente ao kernel em uso ou use o ambiente de laboratório já preparado no repositório.

### 3. Verificar as ferramentas

```bash
which filetop-bpfcc
which dirtop-bpfcc
which fileslower-bpfcc
```

Se algum comando não estiver disponível, a instalação do pacote BCC não foi concluída corretamente.

---

## Estrutura do Lab

Arquivos principais:

- `workload.sh` — gera atividade repetitiva de leitura, escrita e criação de diretórios.
- `README.md` — guia do laboratório.

---

## Passo 1 — Preparar o Sandbox

Crie uma área isolada para o experimento:

```bash
mkdir -p /tmp/ebpf-files-lab
```

Se quiser limpar execuções anteriores:

```bash
rm -rf /tmp/ebpf-files-lab
mkdir -p /tmp/ebpf-files-lab
```

---

## Passo 2 — Gerar Hotspots de I/O

Em um terminal, execute o gerador de carga:

```bash
bash workload.sh /tmp/ebpf-files-lab
```

O script cria uma base de dados pequena e passa a repetir operações em três áreas:

- `hot/cache` para leitura constante.
- `hot/logs` para escrita frequente.
- `hot/tree` para criação e navegação em diretórios.

A ideia é provocar um padrão reconhecível de hotspots para que as ferramentas do BCC tenham algo visível para mostrar.

---

## Passo 3 — Observar Arquivos Mais Ativos com filetop

Em outro terminal, rode:

```bash
sudo filetop-bpfcc
```

O `filetop` mostra os arquivos com maior atividade recente. Durante o workload, espere ver o arquivo de log e o blob de cache entre os itens mais frequentes.

### O que observar

- Leituras repetidas do arquivo de cache.
- Escritas contínuas no log.
- Aumento do volume de acesso conforme o loop roda.

### Perguntas guia

- Qual arquivo aparece com maior frequência?
- O padrão muda se você interromper o workload por alguns segundos?
- Existe diferença entre leitura e escrita no que está sendo exibido?

---

## Passo 4 — Observar Diretórios Mais Ativos com dirtop

Em outro terminal, rode:

```bash
sudo dirtop-bpfcc -d /tmp/ebpf-files-lab
```

O `dirtop-bpfcc` precisa receber os diretórios a observar com `-d`. No exemplo acima, o alvo é o sandbox do laboratório.

### O que observar

- Diretórios onde o workload cria arquivos novos.
- Áreas com muitas operações de metadata.
- Hotspots que não aparecem olhando apenas o nome do arquivo final.

### Perguntas guia

- O hotspot está concentrado em um arquivo único ou em um diretório inteiro?
- A criação de muitos arquivos pequenos aparece com mais destaque do que a leitura do blob grande?

---

## Passo 5 — Detectar Operações Lentas com fileslower

Em outro terminal, rode:

```bash
sudo fileslower-bpfcc 1
```

O `fileslower-bpfcc` recebe o limiar em milissegundos como argumento posicional. No exemplo acima, ele mostra operações acima de 1 ms.

### O que observar

- Operações de criação, cópia ou fechamento com maior latência.
- Picos ocasionais quando o sistema força escrita em disco.
- Diferença entre atividade leve e atividades que envolvem mais metadata.

### Observação importante

Em máquinas muito rápidas ou com muito cache em memória, `fileslower-bpfcc` pode mostrar poucos eventos. Nesse caso, aumente o tamanho do arquivo base no script ou suba o limiar do comando.

Se aparecerem avisos do tipo `Current kernel does not have __vfs_read` ou `cannot attach kprobe, Invalid argument`, mas o comando continuar exibindo a tabela de eventos, isso é esperado no fallback do seu kernel e não indica falha fatal.

---

## Interpretação Inicial

Este primeiro contato com eBPF para arquivos e diretórios deve deixar claro três ideias centrais:

1. Nem toda atividade de I/O é igual: um arquivo pode ser lido muito mais do que outros.
2. O problema pode estar no diretório, não só em um arquivo específico.
3. Operações aparentemente simples podem ficar lentas quando há pressão de I/O, metadata ou sincronização.

Essas três visões são complementares e ajudam a localizar hotspots com rapidez.

---

## Limpeza

Para parar o gerador de carga, use `Ctrl+C` no terminal onde `workload.sh` estiver rodando.

O script recria o sandbox a cada execução, então não é necessário limpar manualmente antes de rodar de novo.

Para limpar o sandbox:

```bash
rm -rf /tmp/ebpf-files-lab
```

---

## Próximos Passos

Depois deste início, a evolução natural do laboratório é:

- substituir as ferramentas prontas por um programa eBPF próprio;
- coletar métricas por processo, usuário ou caminho de arquivo;
- correlacionar hotspots de arquivo com latência de aplicação;
- comparar a observabilidade do BCC com instrumentação em userspace.

---

## Estrutura do Projeto

```
lab-arquivos-diretorios/
├── README.md      # Guia do laboratório
└── workload.sh    # Gerador simples de hotspots de I/O
```
