package embeds

import (
	"fmt"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// VirusTotalResponse é uma estrutura que representa a resposta do VirusTotal após a verificação de um arquivo.
type VirusTotalResponse struct {
	ResponseCode int `json:"response_code"`
	Positives    int `json:"positives"`
	Total        int `json:"total"`
	Scans        map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
	} `json:"scans"`
}

func CreateVirusReportEmbed(m *discordgo.MessageCreate, response VirusTotalResponse, fileName string) *discordgo.MessageEmbed {
	// Verifique se há muitas ameaças
	if len(response.Scans) > 25 {
		return CreateVirusReportMessage(m, response, fileName)
	}

	// Criação da embed com ameaças
	embed := &discordgo.MessageEmbed{
		Title:       "Relatório de Ameaças",
		Description: fmt.Sprintf("## <a:carregando:1163910534081552457> Ameaças encontradas no arquivo: `%s`", fileName),
		Thumbnail: &discordgo.MessageEmbedThumbnail{
			URL: "https://i.imgur.com/5sTjkKy.gif",
		},
		Color: 0xFF0000, // Cor vermelha (personalize conforme necessário)
		Author: &discordgo.MessageEmbedAuthor{
			Name:    m.Author.Username,
			IconURL: m.Author.AvatarURL(""),
		},
	}

	threats := []string{}
	for scan, result := range response.Scans {
		if result.Detected {
			threatText := fmt.Sprintf("Antivírus: %s\nAmeaça: %s", scan, result.Result)
			threatBlock := fmt.Sprintf("```\n%s\n```", threatText)
			threats = append(threats, threatBlock)
		}
	}

	if len(threats) > 0 {
		field := &discordgo.MessageEmbedField{
			Name:   "**Antivírus Detectados e Ameaças encontradas:**",
			Value:  strings.Join(threats, "\n"),
			Inline: false,
		}
		embed.Fields = append(embed.Fields, field)
	} else {
		field := &discordgo.MessageEmbedField{
			Name:   "**Seu arquivo está seguro**\n",
			Value:  "Nenhum antivírus detectou ameaças.",
			Inline: false,
		}
		embed.Fields = append(embed.Fields, field)
		embed.Footer = &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%d de %d antivírus detectaram ameaças", response.Positives, response.Total),
		}
		embed.Description = "## ✅ Nenhuma ameaça foi encontrada!"
		embed.Color = 0x00FF00
	}

	return embed
}

func CreateVirusReportMessage(m *discordgo.MessageCreate, response VirusTotalResponse, fileName string) *discordgo.MessageEmbed {
	message := &discordgo.MessageEmbed{
		Title: "Relatório de Ameaças",
		Color: 0xFF0000, // Cor vermelha (personalize conforme necessário)
		Author: &discordgo.MessageEmbedAuthor{
			Name:    m.Author.Username,
			IconURL: m.Author.AvatarURL(""),
		},
		Thumbnail: &discordgo.MessageEmbedThumbnail{
			URL: "https://i.imgur.com/5sTjkKy.gif", // URL da miniatura (personalize conforme necessário)
		},
	}

	threats := []string{}
	for scan, result := range response.Scans {
		if result.Detected {
			threatText := fmt.Sprintf("Antivírus: %s\nAmeaça: %s", scan, result.Result)
			threatBlock := fmt.Sprintf("```\n%s\n```", threatText)
			threats = append(threats, threatBlock)
		}
	}

	if len(threats) > 0 {
		message.Fields = append(message.Fields, &discordgo.MessageEmbedField{
			Name:   "Antivírus Detectados e Ameaças encontradas:",
			Value:  strings.Join(threats, "\n"),
			Inline: false,
		})
		message.Footer = &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%d de %d antivírus detectaram ameaças", response.Positives, response.Total),
		}
		message.Thumbnail = &discordgo.MessageEmbedThumbnail{
			URL: "https://i.imgur.com/5sTjkKy.gif", // URL da miniatura (personalize conforme necessário)
		}
	} else {
		message.Description = "Seu arquivo está seguro. Nenhum antivírus detectou ameaças."
		message.Color = 0x00FF00 // Cor verde para indicar que está seguro
		message.Footer = &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%d de %d antivírus detectaram ameaças", response.Positives, response.Total),
		}
	}

	// Adicionar o nome do arquivo
	message.Fields = append(message.Fields, &discordgo.MessageEmbedField{
		Name:   "**Nome do Arquivo:**",
		Value:  fmt.Sprintf("`%s`", fileName), // Use fmt.Sprintf para formatar a string
		Inline: false,
	})

	return message
}
