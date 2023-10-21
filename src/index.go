package main

import (
	"fmt"
	"os"
	"strings"
	"virustotal/src/config/embeds"
	"virustotal/src/config/filesutils"

	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
)

var discordToken = ""     // Token do Discord do bot
var virusTotalAPIKey = "" // Chave da API do VirusTotal

func main() {
	// Carregue as variáveis de ambiente do arquivo .env
	if err := godotenv.Load(); err != nil {
		fmt.Println("Erro ao carregar o arquivo .env")
	}

	// Obtenha o token do bot do Discord a partir das variáveis de ambiente
	discordToken := os.Getenv("BOT_TOKEN")

	// Crie uma nova sessão do Discord
	dg, err := discordgo.New("Bot " + discordToken)
	if err != nil {
		fmt.Println("Erro ao criar a sessão do Discord:", err)
		return
	}

	// Adicione um handler para lidar com mensagens recebidas
	dg.AddHandler(messageCreate)

	// Abra a conexão com o Discord
	err = dg.Open()
	if err != nil {
		fmt.Println("Erro ao abrir a conexão com o Discord:", err)
		return
	}

	fmt.Println("O bot está em execução. Pressione CTRL+C para sair.")
	select {}
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Verifique se o autor da mensagem é o próprio bot
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Verifique se a mensagem começa com "!verificar"
	if !strings.HasPrefix(m.Content, "!verificar") {
		return
	}

	// Verifique se a mensagem não contém anexos de imagem (você pode personalizar isso)
	if len(m.Attachments) == 0 {
		// Se não houver anexos, avise o usuário
		s.ChannelMessageSend(m.ChannelID, "Você deve anexar um arquivo para verificar. Use `!verificar` com um arquivo anexado.")
		return
	}

	// Verifique se a mensagem não contém anexos de imagem (você pode personalizar isso)
	for _, attachment := range m.Attachments {
		if strings.HasPrefix(attachment.ContentType, "image/") {
			return
		}
	}

	// Se houver anexos na mensagem, faça o seguinte:
	if len(m.Attachments) > 0 {
		// Enviando a mensagem "Aguarde uns segundos..." antes de processar o arquivo
		waitMessage, _ := s.ChannelMessageSend(m.ChannelID, "<a:carregando:1163910534081552457> Aguarde uns segundos...")

		for _, attachment := range m.Attachments {
			fileName := attachment.Filename
			fileURL := attachment.URL
			filePath := filesutils.DownloadFile(fileURL, fileName)

			if filePath == "" {
				s.ChannelMessageSend(m.ChannelID, "Erro ao baixar o arquivo.")
				s.ChannelMessageDelete(m.ChannelID, waitMessage.ID) // Exclui a mensagem "Aguarde uns segundos..."
				return
			}

			response, err := filesutils.CheckVirus(filePath)

			if err != nil {
				s.ChannelMessageSend(m.ChannelID, "Erro ao analisar o arquivo.")
				s.ChannelMessageDelete(m.ChannelID, waitMessage.ID) // Exclui a mensagem "Aguarde uns segundos..."
				return
			}

			// Exclua a mensagem do usuário que enviou o arquivo
			s.ChannelMessageDelete(m.ChannelID, m.ID)

			// Crie a embed com base no resultado da verificação
			virusTotalResponse := embeds.VirusTotalResponse(response)

			// Use virusTotalResponse para criar a embed
			embed := embeds.CreateVirusReportEmbed(m, virusTotalResponse)

			// Exclua a mensagem "Aguarde uns segundos..."
			s.ChannelMessageDelete(m.ChannelID, waitMessage.ID)

			// Envie a embed criada
			s.ChannelMessageSendEmbed(m.ChannelID, embed)
			os.Remove(filePath)
		}
	}
}
