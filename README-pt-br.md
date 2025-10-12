# Network Interface Profile Manager (NIPM)

NIPM (Network Interface Profile Manager) é uma ferramenta CLI para Linux que permite gerenciar interfaces de rede e suas conexões (Wi-Fi ou Ethernet) por meio de perfis.
Suporta criação, manutenção e alternância automática entre perfis de rede de forma dinâmica e segura, sem depender de um daemon residente, oferecendo maior controle e flexibilidade sobre as interfaces.

---

## Visão Geral

O **NIPM** trabalha diretamente com as ferramentas de rede padrão do Linux:

* [`dhcpcd.conf`](https://wiki.archlinux.org/title/Dhcpcd)
* [`wpa_supplicant.conf`](https://wiki.archlinux.org/title/Wpa_supplicant)

Automatiza a criação e atualização desses arquivos de configuração, garantindo conformidade com a sintaxe oficial e reduzindo erros manuais.

O NIPM prioriza interfaces de rede com base em métricas definidas pelo usuário e reconecta automaticamente em caso de falha, garantindo uma experiência de conexão confiável.

---

## Funcionalidades Principais

* **Criação e atualização de perfis**: com comando `create-profile`, é possível definir SSID, senha (PSK) e prioridade (métrica) para cada interface, quanto menor a métrica da interface, mais prioridade ela irá ter.
* **Gerenciamento centralizado**: mantém todas as configurações organizadas no diretório de perfil do usuário (`~/.config/nipm`) que só é acessível com permissões de root, por motivos de segurança.
* **Suporte a múltiplas interfaces**: alterna dinamicamente entre interfaces ativas, mantendo sempre a conexão prioritária.
* **Monitoramento contínuo**: modo em segundo plano (`-b`) verifica a disponibilidade da interface e reconecta automaticamente em caso de falha. Também é possível definir o tempo para cada verificação, através da opção (`-s`) e em seguida o valor em segundos.
* **Remoção fácil de perfis**: é possível remover perfis individuais ou todos os perfis de uma só vez.
* **Compatibilidade**: utiliza ferramentas padrão do Linux (`dhcpcd`, `wpa_supplicant`) sem dependências externas complexas.

---

## Instalação

```bash
# Clonar o repositório
git clone https://github.com/gusprojects008/nipm.git
cd nipm
````

Certifique-se de ter Python 3.13+, `dhcpcd` e `wpa_supplicant` instalados.

---

## Uso

```bash
# Mostrar ajuda
sudo python3 nipm.py --help

# Criar ou atualizar um perfil de rede
sudo python3 nipm.py create-profile

# Listar todos os perfis salvos
sudo python3 nipm.py list-profiles

# Remover um perfil específico
sudo python3 nipm.py remove-profile <interface>

# Remover todos os perfis
sudo python3 nipm.py remove-profiles

# Iniciar conexão com monitoramento de interfaces (background)
sudo python3 nipm.py start -b

# Iniciar conexão sem monitoramento (modo único)
sudo python3 nipm.py start
```

> Durante a criação do perfil, será solicitado:
>
> * Nome da interface (ex: `wlan0`)
> * SSID da rede
> * Senha (PSK) da rede
> * Métrica (prioridade da interface, padrão = 100)

---

## Estrutura de Configuração

* Diretório de configuração do usuário: `~/.config/nipm/`
* Arquivo principal de perfis: `nipm-config.json`
* Arquivos de configuração gerados para cada interface:

  * `wpa-supplicant-<ifname>.conf`
  * `dhcpcd-<ifname>.conf`

Todos os arquivos e diretórios são criados com permissões restritas (`740`) para maior segurança.

---

## Requisitos

* Python 3.13+
* `dhcpcd`
* `wpa_supplicant`
* Permissões de administrador (sudo)

#### Certifique-se de que não haja daemons ou serviços de rede em execução (por exemplo, iwd ou NetworkManager) antes de executar o programa.

---

## Pontos Fortes

* Confiabilidade e automação para múltiplas interfaces wireless ou ethernet.
* Flexibilidade para uso em modo monitoramento ou execução única.
* Integração nativa com ferramentas padrão Linux, sem dependências externas.
* Fácil manutenção de perfis de rede em sistemas multi-interface.

---

## Licença

MIT License – consulte [LICENSE](LICENSE) para detalhes.
