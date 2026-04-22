# Laboratório eBPF — de Arquivos para Correlação Arquivo ↔ Rede

> Extensão de um laboratório introdutório de observabilidade de arquivos com
> `filetop`/`dirtop`/`fileslower` para um programa eBPF próprio que cruza I/O
> de arquivo com I/O de rede por processo. A adição da camada de rede alinha
> o trabalho aos objetivos da disciplina de **Redes Programáveis** (eBPF/XDP,
> telemetria, observabilidade da stack do Linux).

[![Linux](https://img.shields.io/badge/Linux-required-blue?logo=linux)](https://www.kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-BCC-orange)](https://ebpf.io)

---

## Histórico do repositório

A primeira versão deste lab (que continua neste diretório, em `workload.sh` e
nas referências a `filetop`/`dirtop`/`fileslower`) explorava apenas o
subsistema de arquivos com ferramentas prontas do BCC. Era um bom começo para
ver eBPF funcionando, mas o tema "arquivos e diretórios" não toca o eixo
central da disciplina, que é redes programáveis.

Para fechar essa lacuna sem descartar o trabalho inicial, **adicionamos uma
camada de rede** sobre a mesma base. Em vez de usar apenas ferramentas
prontas, escrevemos um programa eBPF próprio que observa simultaneamente o
caminho de arquivos e o caminho de rede do kernel, e correlaciona os dois por
processo. O tema continua "arquivos e diretórios", mas agora as perguntas
viram sobre redes: *quais processos são ponte entre disco e rede?*

## O que esta versão adiciona

Comparado à versão original do repositório:

| Arquivo                  | Status         | Função                                                         |
|--------------------------|----------------|----------------------------------------------------------------|
| `workload.sh`            | preservado     | gerador de I/O original (só arquivo), do passo introdutório    |
| `README.md`              | **reescrito**  | esta documentação                                              |
| `netfile_top.py`         | **novo**       | programa eBPF próprio, correlação arquivo ↔ rede por PID       |
| `workload_netfile.sh`    | **novo**       | sobe 4 workers com perfis de I/O controlados para o experimento |
| `validate.sh`            | **novo**       | oráculo automatizado que verifica o comportamento esperado     |

O programa próprio é o coração da adição: ele anexa cinco pontos no kernel e
mantém um mapa por PID com bytes de arquivo, bytes de rede e chamadas a
`sendfile()`, tudo calculado dentro do kernel sem custo de copiar eventos para
userspace.

## Motivação

Padrões comuns em servidores e aplicações distribuídas misturam arquivo e rede
no mesmo processo:

- servidores web servindo conteúdo estático (lê arquivo → envia pela rede);
- agentes de backup ou replicação (lê rede → grava arquivo);
- caches locais que populam do remoto;
- cenários de exfiltração de dados (lê arquivo → manda pela rede).

Ferramentas tradicionais como `filetop` e `tcptop` mostram cada lado em
separado. Nenhuma das duas responde diretamente *"quais processos estão
fazendo as duas coisas ao mesmo tempo?"*. O `netfile_top.py` responde.

---

## Ambiente

```
┌──────────────────────────────────────────────┐
│                Host Linux                    │
│                                              │
│  Terminal A: workload_netfile.sh             │
│     ├─ http-serve  (arquivo → rede)          │
│     ├─ curl-loop   (rede → arquivo)          │
│     ├─ file-only   (só arquivo)              │
│     └─ net-only    (só rede, iperf3)         │
│                                              │
│  Terminal B: sudo python3 netfile_top.py     │
│                                              │
│  Terminal C: sudo ./validate.sh              │
│                                              │
│  Sandbox: /tmp/ebpf-netfile-lab              │
└──────────────────────────────────────────────┘
```

Todo o tráfego é loopback. Isso basta para exercitar os caminhos de kernel que
queremos observar: `tcp_sendmsg`, `tcp_cleanup_rbuf`, `vfs_read`, `vfs_write`
e o tracepoint de `sendfile`.

---

## Pré-requisitos

### Kernel e permissões

- Linux recente com suporte a eBPF (testado em 6.18).
- Acesso de `sudo`.
- Headers do kernel alinhados com o kernel em execução
  (`/lib/modules/$(uname -r)/build/Makefile` precisa existir).

### Pacotes

Em Arch/Manjaro:

```bash
sudo pacman -Syu --needed bcc bcc-tools python-bcc iperf3
```

Em Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) iperf3
```

### Verificação

```bash
python3 -c "from bcc import BPF; print('bcc ok')"
which iperf3 curl python3
```

Se o `import` do BCC falhar por causa de headers desalinhados (comum em
Manjaro logo após `pacman -Syu` sem reboot), reinicie a máquina para o kernel
passar a casar com o pacote de headers.

---

## Parte 1 — Exploração inicial com ferramentas prontas

Esta parte é a versão original do lab, preservada. Serve como aquecimento
antes de olhar para o programa próprio.

Em um terminal, gere atividade de arquivo:

```bash
bash workload.sh /tmp/ebpf-files-lab
```

Em outros terminais, observe com ferramentas prontas (os binários em Arch se
chamam `filetop`, `tcptop` etc., sem sufixo `-bpfcc`):

```bash
sudo filetop   # arquivos mais ativos
sudo tcptop    # conexões TCP mais ativas
```

A observação importante da Parte 1 é que cada ferramenta responde metade da
pergunta. Falta a ponte entre as duas — que é o objeto da Parte 2.

---

## Parte 2 — Programa próprio: correlação arquivo ↔ rede

### Como funciona

`netfile_top.py` é um programa em BCC (Python + C eBPF) que anexa cinco
pontos no kernel e mantém um mapa por PID:

| Hook                               | O que mede                                              |
|------------------------------------|---------------------------------------------------------|
| `kprobe:vfs_read`                  | bytes lidos do sistema de arquivos (só arquivos regulares) |
| `kprobe:vfs_write`                 | bytes escritos no sistema de arquivos (só arquivos regulares) |
| `kprobe:tcp_sendmsg`               | bytes enviados via TCP                                  |
| `kprobe:tcp_cleanup_rbuf`          | bytes recebidos via TCP                                 |
| `tracepoint:sys_enter_sendfile64`  | chamadas a `sendfile()` — sinal causal forte            |

O filtro "só arquivos regulares" é feito dentro do próprio programa eBPF,
checando `S_ISREG(file->f_inode->i_mode)`. Sem esse filtro, `vfs_read`/
`vfs_write` também contariam sockets, pipes e tty, o que inflaria a coluna de
arquivo para processos puramente de rede (como o `iperf3`).

A cada janela de N segundos, o userspace calcula por PID um **score de
correlação**:

```
corr(pid, janela) = min(file_rd + file_wr, tcp_tx + tcp_rx)
```

A intuição é direta: um processo que faz 100 MB de arquivo *e* 100 MB de rede
na mesma janela recebe score 100 MB. Um que faz 100 MB só de uma das duas
recebe 0. O topo do ranking é o conjunto de processos que são **ponte** entre
arquivo e rede.

### Workload sintético (`workload_netfile.sh`)

Para validar o programa precisamos de um ambiente com perfis de I/O
conhecidos. O script sobe quatro processos em paralelo:

| Worker        | Perfil esperado                       | Correlação esperada |
|---------------|---------------------------------------|---------------------|
| `http-serve`  | lê arquivo, envia pela rede           | alta                |
| `curl-loop`   | recebe da rede, grava arquivo         | alta                |
| `file-only`   | só lê/escreve arquivo                 | 0                   |
| `net-only`    | só envia/recebe rede (iperf3)         | 0                   |

Detalhes importantes:

- `http-serve` é um `python3 -m http.server` servindo um blob de 8 MB.
- `curl-loop` é um downloader Python de longa duração (um único PID estável).
  Não usamos `bash + curl` em loop porque cada `curl` seria um PID efêmero
  diferente, impossível de rastrear deterministicamente.
- `net-only` é um `iperf3 -c -t 86400` (uma única invocação longa) e
  `net-only-srv` é o `iperf3 -s` correspondente.
- Cada PID é salvo em `/tmp/ebpf-netfile-lab/.pids/<nome>` para o validador
  encontrar sem ambiguidade.

### Como rodar

**Terminal A** — sobe os workers:

```bash
bash workload_netfile.sh
```

**Terminal B** — observa em tempo real:

```bash
sudo python3 netfile_top.py -i 2 -n 10
```

Saída típica (após alguns segundos de aquecimento):

```
=== 14:05:02 (janela 2s) ===
    PID COMM             FILE_RD  FILE_WR   TCP_TX   TCP_RX SENDFILE     CORR
 233406 python3            3.3G     0.0B     3.3G     0.0K        0     3.3G
 233408 python3            3.3G     3.3G     0.0K     3.3G        0     3.3G
 233484 iperf3             0.0B     0.0B    30.0G    30.0G        0     0.0B
 233409 python3            2.7G     2.7G     0.0K     0.0K        0     0.0B
```

`http-serve` e `curl-loop` lideram pelo score. `file-only` e `net-only`
aparecem com valores enormes em *uma* das dimensões, mas correlação zero.

Opções úteis do `netfile_top.py`:

- `-i N` — janela em segundos (padrão 2).
- `-n N` — linhas exibidas na tabela de texto (padrão 10).
- `-j` — emite uma linha JSON por janela, sem truncar; conveniente para
  consumir com outro script (é assim que o `validate.sh` trabalha).
- `--min-bytes N` — esconde PIDs abaixo desse total na janela.

---

## Validação automática

Com o workload ainda rodando no Terminal A, em outro terminal:

```bash
sudo ./validate.sh
```

O script:

1. Lê os PIDs salvos em `/tmp/ebpf-netfile-lab/.pids/`.
2. Executa `netfile_top.py -j` por 20 segundos.
3. Agrega as janelas por PID e verifica as invariantes:
   - `http-serve` tem correlação > 0;
   - `curl-loop` tem correlação > 0;
   - `file-only` tem menos de 1 MB de bytes de rede;
   - `net-only` tem menos de 1 MB de bytes de arquivo.

Saída bem-sucedida termina em `VALIDACAO: OK`.

### Resultado medido (execução de referência)

Execução em kernel 6.18.18-1-MANJARO, janela de 20 s:

| Worker       | Rank | File (GB) | Net (GB) | Correlação (GB) |
|--------------|------|-----------|----------|-----------------|
| `http-serve` | 1    | 34        | 33       | **33**          |
| `curl-loop`  | 2    | 33        | 33       | **33**          |
| `net-only`   | 8    | 0         | 299      | 0               |
| `file-only`  | 10   | 27        | 0        | 0               |

O ranqueamento casa exatamente com o esperado: os dois processos "ponte"
dominam o topo; os "puros" caem para correlação zero (e aparecem no ranking
global abaixo de processos do sistema com pequena atividade correlacionada,
mas não-zero).

---

## Interpretação

Três leituras caem naturalmente deste experimento:

1. **Correlação não é causalidade.** Um PID no topo está fazendo as duas
   coisas na mesma janela; os bytes podem não ser os mesmos. Na prática, o
   padrão identifica muito bem servidores web, agentes de sincronização e
   pipelines de exfiltração.
2. **`sendfile()` é o único sinal estritamente causal** no conjunto. Quando a
   contagem de `SENDFILE` sobe, temos certeza de que aquele processo está
   mandando bytes de arquivo direto para um socket (zero-copy).
3. **Uma só ferramenta não vê o fenômeno.** `filetop` veria o lado do disco;
   `tcptop` veria o lado da rede. Só o cruzamento por PID em uma janela
   comum produz a ordenação útil.

---

## Limitações

- **`tcp_sendmsg` conta bytes requisitados**, não bytes confirmados na rede.
  Em regime normal a diferença é desprezível; sob congestão, pode
  superestimar.
- **Causalidade byte-a-byte** exigiria rastrear buffers atravessando do fd de
  arquivo para o fd de socket. É possível, mas muito mais pesado. Optamos
  por correlação temporal por PID e explicitamos a limitação no relatório.
- **Loopback infla os números de rede.** Um `iperf3 -c 127.0.0.1` conta os
  bytes em `tx` e `rx` no mesmo host. Para medição real, repetir entre duas
  VMs ou dois containers em bridges separadas.
- **`comm` pode ser de thread.** O kernel retorna o comm da thread corrente
  em `bpf_get_current_comm`. Em aplicações multi-thread como o `http.server`
  do Python, o nome exibido pode ser de uma thread de trabalho
  (`Thread-NNNN`). A identificação confiável continua sendo o PID.

---

## Próximos passos

- Distinguir envio local (loopback) de remoto via família/endereço do
  `struct sock`.
- Histograma de latência por operação (estilo `fileslower`), correlacionado
  ao socket ativo.
- Migrar o programa de BCC para libbpf+CO-RE e comparar tempo de carga e
  footprint.
- Rodar o workload em dois containers (cliente/servidor) e medir o overhead
  do eBPF com e sem as probes anexadas.
- Empacotar `netfile_top.py` também como programa XDP, contando na entrada da
  interface e comparando com a visão de `tcp_*` por PID.

---

## Limpeza

`Ctrl+C` no terminal do `workload_netfile.sh` derruba todos os workers. Para
apagar o sandbox:

```bash
rm -rf /tmp/ebpf-netfile-lab /tmp/ebpf-files-lab
```
