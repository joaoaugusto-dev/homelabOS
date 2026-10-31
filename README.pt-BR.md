# homelabOS

Um painel minúsculo, sem dependências, para o servidor de casa, escrito em C. Dois programas, sem frameworks, sem banco de dados, sem etapa de build de JavaScript.

- **homelabOS**: métricas ao vivo (CPU, memória, temperatura, rede, potência com custo de energia), gerenciador de arquivos de uma pasta compartilhada, atalhos e login com uma segunda conta opcional de "gestor".
- **Hospedagem** (`hosting/`): plataforma de apps no estilo Dokploy. Deploy pelo GitHub (webhook ou verificação periódica) ou por upload de zip/tar.gz, execução em container (Podman rootless) ou em processo com sandbox, bancos PostgreSQL/MariaDB, publicação por Cloudflare Tunnel e estatísticas de visitantes sem guardar IP.

| Visão geral | Hospedagem: aplicações |
|---|---|
| ![Visão geral](docs/screens/os-geral.png) | ![Aplicações](docs/screens/hosting-apps.png) |
| ![Arquivos](docs/screens/os-arquivos.png) | ![Estatísticas](docs/screens/hosting-stats.png) |

Mais: [login](docs/screens/login.png) · [sistema](docs/screens/os-sistema.png) · [energia](docs/screens/os-energia.png) · [atalhos](docs/screens/os-atalhos.png) · [celular](docs/screens/os-mobile.png) · [nova aplicação](docs/screens/hosting-nova.png) · [domínios](docs/screens/hosting-dominios.png)

## Começando

**Deixe um agente de IA instalar.** Cole este link no seu agente (Claude Code, Codex etc.) na máquina onde quer instalar. Ele lê o hardware, faz poucas perguntas, compila, instala e ajusta a configuração para aquela máquina. As senhas e o `sudo` ficam com você.

```
https://raw.githubusercontent.com/joaoaugusto-dev/homelabOS/main/INSTALL-AGENT.md
```

Ou instale à mão:

Precisa de Linux, `gcc` e `make`. A Hospedagem usa também `git`, `curl`, `python3` e, opcionalmente, `podman`, PostgreSQL, MariaDB e `cloudflared`.

```sh
make                 # compila homelabos/homelabos e hosting/hosting
make test            # testes herméticos (nada toca no seu sistema)

# testar localmente, sem root
cp homelabos/homelab.conf.example homelabos/homelab.conf
./homelabos/homelabos --hash          # digite a senha e cole a linha password_hash no homelab.conf
(cd homelabos && ./homelabos -c homelab.conf)     # http://127.0.0.1:8080
```

Instalar os dois como serviços systemd (código em `/opt`, do root; dados em `/var/lib/homelabos`, de um usuário dedicado):

```sh
sudo bash deploy/install.sh --hosting
```

Por padrão os painéis escutam em `127.0.0.1`. Para acessar pela rede local, ponha `bind=<ip do servidor>` na configuração. O painel é HTTP puro: use Tailscale/WireGuard ou um proxy reverso com TLS antes de sair de uma rede confiável.

A Hospedagem usa o login do homelabOS: pergunta à porta do homelabOS quem é o dono do cookie e qual o papel. Detalhes em [`hosting/README.md`](hosting/README.md).

## Segurança, em resumo

Os dois programas foram endurecidos partindo do princípio de que o código é público e o atacante pode lê-lo. Leia o [`SECURITY.md`](SECURITY.md) para o modelo de ameaças, o que **não** é protegido e como reportar uma vulnerabilidade.

## Licença

MIT. Veja [`LICENSE`](LICENSE).
