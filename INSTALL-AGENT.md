# Instalação do homelabOS guiada por agente

> **Para o agente de IA que recebeu este arquivo:** o usuário quer o homelabOS instalado **nesta máquina**, ajustado ao hardware dela. Siga as fases abaixo em ordem. Você tem acesso ao shell; use-o. Não peça ao usuário para digitar o que você mesmo pode descobrir.

homelabOS = painel em C (métricas, arquivos, atalhos, login) + Hospedagem (apps por GitHub/zip, Podman, bancos, Cloudflare Tunnel). Sem dependências além de `gcc` e `make`. Repositório: `https://github.com/joaoaugusto-dev/homelabOS`.

## Regras de conduta (valem para tudo)

1. **Mostre antes de mudar.** Cada fase termina com um resumo curto do que será feito; peça um "ok" antes das fases 4 em diante.
2. **Senhas nunca passam por você.** Peça ao usuário para rodar `! sudo bash deploy/install.sh ...` ele mesmo (ou digitar a senha quando o script perguntar). Nunca coloque senha em argumento de comando, log, arquivo de histórico ou commit.
3. **`sudo` é do usuário.** Se `sudo -n true` falhar, entregue o comando exato e espere. Não tente contornar.
4. **Não apague nada que já exista** (outro serviço na porta 80, `/etc/homelabos`, dados em `/var/lib/homelabos`). Se achar, pare e pergunte: atualizar (o `install.sh` é idempotente e preserva as confs) ou instalar em outra porta.
5. **Painel é HTTP puro.** Nunca configure `bind=0.0.0.0` sem avisar e sem senha definida. Prefira o IP da LAN ou Tailscale.
6. **Não abra portas no roteador/firewall** sem pedir.

## Fase 1: acesso ao código

```sh
git clone https://github.com/joaoaugusto-dev/homelabOS.git ~/homelabOS-src && cd ~/homelabOS-src
```

- Se o clone falhar com 404/autenticação, o repositório ainda é **privado**: peça ao usuário um token/`gh auth login`, ou que ele envie o código (`git archive`/zip). Não invente outra fonte.
- Se `git` não existir, instale pelo gerenciador de pacotes da distro (fase 3).

## Fase 2: diagnóstico do hardware (somente leitura)

Rode e **guarde os resultados** — a configuração depende deles:

```sh
uname -m; . /etc/os-release; echo "$PRETTY_NAME"; nproc
grep -m1 'model name\|Model' /proc/cpuinfo; grep MemTotal /proc/meminfo
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,ROTA; df -h / /srv /home 2>/dev/null
ip -brief addr; ip route | head -3
ls /sys/class/powercap/ 2>/dev/null; ls /sys/class/hwmon/*/name 2>/dev/null | xargs -r cat
ls /sys/class/thermal/ 2>/dev/null; ls /sys/class/power_supply/ 2>/dev/null
uname -r                      # Landlock (sandbox dos apps) pede kernel >= 5.13
command -v gcc make git curl python3 podman psql mariadb cloudflared tailscale systemctl
ss -ltnp 2>/dev/null | grep -E ':(80|8080|8430)\s'   # portas já ocupadas
sudo -n true 2>&1 | head -1
```

### Como o hardware muda a instalação

| Achado | Decisão |
|---|---|
| `systemctl` ausente (não é systemd) | Não use `install.sh`. Rode o binário com a conf e crie o serviço no init da distro (OpenRC/runit/s6), mantendo os mesmos usuário, pastas e permissões do script. |
| Distro sem `apt` (Fedora, Arch, Alpine) | `install.sh` usa `apt-get` só na parte da Hospedagem. Instale os equivalentes (`podman`, `shadow-utils`/`uidmap`, `passt`, `postgresql`, `mariadb`, `python3`, `git`, `curl`) à mão e rode o script mesmo assim, ou edite o bloco `apt-get` em uma cópia. |
| `uname -m` = `aarch64`/`armv7l` (Raspberry Pi, SBC) | Compila normal com `gcc`. Sem RAPL: a potência vem só de `idle_w`/`max_w`/`offset_w` (estimativa). Temperatura vem de `cpu_thermal`/`thermal_zone0`. |
| `/sys/class/powercap/intel-rapl:0` presente (Intel) | Potência real do processador. `offset_w` = consumo do resto (placa, discos, fonte). Valores iniciais na tabela abaixo; o usuário calibra com medidor de tomada. |
| AMD (`k10temp`) sem RAPL legível | Mesma estimativa por `idle_w`/`max_w`. |
| RAM < 2 GB | **Pule** PostgreSQL e MariaDB (ou instale só um). Hospedagem funciona sem bancos. Avise que builds de container podem estourar memória; sugira swap. |
| RAM 2–4 GB | Instale a Hospedagem, mas só um banco, e só se o usuário for usar. |
| Sem kernel ≥ 5.13 | Sandbox Landlock desligado (o log avisa). Diga isso ao usuário; considere `sandbox=0` explícito. |
| Disco rotativo (`ROTA=1`) só | Funciona; avise que builds e bancos serão lentos. Se houver um segundo disco, sugira `root=` (arquivos) e dados lá. |
| Bateria (`BAT0`) | Notebook como servidor: o painel mostra a bateria. Sugira desligar suspensão ao fechar a tampa (`HandleLidSwitch=ignore` em `logind.conf`) **só se o usuário concordar**. |
| Várias interfaces de rede | Pergunte qual IP usar no `bind=`. Prefira IP fixo/reserva DHCP; avise que, se o IP mudar, o painel deixa de abrir. |
| Porta 80 ocupada | Use outra (`port=8080`) e informe; o `install.sh` assume 80, então ajuste `/etc/homelabos/homelab.conf` e `dash_ports=` em `hosting.conf` depois. |

Valores iniciais de potência (ajuste ao que o diagnóstico mostrou; são estimativas):

| Máquina | `idle_w` | `max_w` | `offset_w` |
|---|---|---|---|
| Raspberry Pi 4/5, SBC | 3 | 8 | 1 |
| Mini PC / NUC (N100, i3-i5 mobile) | 6 | 25 | 5 |
| Desktop comum | 30 | 100 | 15 |
| Notebook | 8 | 35 | 5 |

## Fase 3: perguntas ao usuário (todas de uma vez, no máximo 5)

Sugira o padrão entre parênteses para cada uma:

1. **Quem acessa?** Só esta máquina / LAN / também fora de casa (Tailscale ou Cloudflare). → define `bind=` e a fase 6.
2. **Nome do administrador?** (`admin`)
3. **Segunda conta "gestor"** (vê só o painel, sem arquivos nem desligar)? Qual o nome? (nenhuma)
4. **Instalar a Hospedagem?** (sim se RAM ≥ 2 GB e o usuário quer rodar apps/sites; senão só o painel)
5. **Pasta compartilhada do gerenciador de arquivos?** (`/srv/compartilhado`; ou o ponto de montagem do disco grande)

Depois confirme o plano em uma tabela: IP/porta, usuário, pastas, pacotes a instalar, o que será ignorado por causa do hardware.

## Fase 4: pacotes e compilação

Instale o que faltar (no Debian/Ubuntu: `sudo apt-get install -y build-essential git curl`; Hospedagem também precisa de `python3`, e `podman` se o usuário quiser containers). Depois:

```sh
make && make test        # make test é hermético: não toca no sistema. Se falhar, pare e mostre a saída.
```

## Fase 5: instalação

Peça ao usuário para rodar (ele digita a senha do admin quando o script pedir; o script pergunta o IP e o nome do admin, responda com o que ele escolheu na fase 3):

```sh
! sudo bash deploy/install.sh --hosting      # sem --hosting se ele não quis a Hospedagem
```

Depois do script, **ajuste a conf ao hardware** (edite `/etc/homelabos/homelab.conf`; precisa de sudo, entregue o comando ao usuário se necessário):

- `idle_w`, `max_w`, `offset_w` conforme a tabela da fase 2 (acrescente as linhas, o instalador não as cria).
- `manager=NOME` se ele pediu gestor; depois `sudo systemctl restart homelabos`. A senha do gestor é definida por convite de uso único: veja `deploy/invite-manager.sh` (ou, na própria máquina, `/opt/homelabos/homelabos/homelabos -c /etc/homelabos/homelab.conf --invite-manager`) e entregue o código ao usuário, nunca por log público.
- `root=` se ele escolheu outra pasta compartilhada (crie com dono `homelabos`).
- Hospedagem: `/etc/homelabos/hosting.conf` já recebe `bind`, `admin` e `dash_ports`. Em máquina com pouca RAM não instale os bancos; o `install.sh` instala ambos, então, se for o caso, informe e remova/desabilite (`systemctl disable --now mariadb`) **só com o ok do usuário**.

Todas as opções estão comentadas em `homelabos/homelab.conf.example` e `hosting/hosting.conf.example`.

## Fase 6: acesso de fora (somente se pedido na pergunta 1)

- **Tailscale** (recomendado, sem abrir porta): `curl -fsSL https://tailscale.com/install.sh | sh` e `sudo tailscale up` (o login é feito pelo usuário no navegador). Depois use o IP `100.x` em `bind=` ou acesse pelo IP da LAN via subnet/serve.
- **Cloudflare Tunnel** (para publicar apps): `cloudflared` instalado e `cloudflared tunnel login` feito pelo usuário; depois `cert_domain=` em `hosting.conf`. Os túneis dos apps são criados pelo próprio painel.

## Fase 7: verificação (obrigatória antes de dizer "pronto")

```sh
systemctl is-active homelabos hosting
curl -s -o /dev/null -w '%{http_code}\n' http://<bind>:<porta>/        # 200
curl -s -o /dev/null -w '%{http_code}\n' http://<bind>:8430/           # 200 ou redirecionamento, se instalou a Hospedagem
journalctl -u homelabos -u hosting -n 30 --no-pager
```

Confira também: o painel mostra temperatura e potência coerentes (se "0 W" ou "--", revise a tabela de hardware); o login do admin funciona (o usuário testa no navegador). Se algo falhar, leia o `journalctl`, corrija a conf e reinicie; não reinstale por reflexo.

## Fase 8: entrega

Resuma em poucas linhas: URL do painel e da Hospedagem, onde estão a conf (`/etc/homelabos/`), código (`/opt/homelabos`, do root), dados (`/var/lib/homelabos`), como atualizar (`git pull && make && sudo bash deploy/install.sh --hosting`, que preserva as confs), como calibrar a potência com um medidor de tomada, e o que ficou de fora por causa do hardware. Pergunte se quer apagar o clone `~/homelabOS-src` (os binários já estão em `/opt`).

## Segurança, em uma linha

Leia `SECURITY.md` se o usuário for expor o painel além da rede de confiança: HTTP puro exige Tailscale/WireGuard ou proxy reverso com TLS.
