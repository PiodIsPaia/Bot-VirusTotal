# Bot de Verificação de Arquivos com o VirusTotal

Este é um bot para Discord que permite verificar se um arquivo é seguro ou se contém ameaças usando o serviço VirusTotal. O bot faz o download do arquivo enviado pelo usuário, calcula seu hash SHA256 e o envia para o VirusTotal para análise. Em seguida, exibe um relatório no canal do Discord com os resultados da verificação.

## Como Usar

1. Clone este repositório:

- git clone https://github.com/iFariasZ/Ilusion-Bot-VirusTotal



2. Instale as dependências:

- `go mod tidy`


3. Configure as variáveis de ambiente:
- Crie um arquivo `.env` na raiz do projeto e configure as seguintes variáveis:
  - `BOT_TOKEN` - Token do seu bot do Discord.
  - `VT_TOKEN` - Chave da API do VirusTotal.


4. Execute o bot: go run ./src/index.go


5. Use o bot:
- No Discord, envie o comando `!verificar` com um arquivo anexado para que o bot realize a verificação.
- O bot responderá com um relatório das ameaças encontradas no arquivo, se houver alguma.

## Personalização

- Você pode personalizar a mensagem de "Aguarde uns segundos..." que o bot envia enquanto verifica o arquivo.
- Você pode personalizar a cor da embed de relatório alterando o valor da cor no código.

## Dependências

Este projeto faz uso das seguintes bibliotecas externas:
- `github.com/bwmarrin/discordgo` - Para interação com a API do Discord.
- `github.com/go-resty/resty/v2` - Para fazer solicitações HTTP ao serviço VirusTotal.
- `github.com/joho/godotenv` - Para carregar as variáveis de ambiente do arquivo `.env`.

## Notas

Certifique-se de que o bot tenha as permissões adequadas para excluir mensagens no servidor.