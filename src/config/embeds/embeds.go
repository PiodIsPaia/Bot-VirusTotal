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

// CreateVirusReportEmbed cria uma embed com informações sobre ameaças encontradas.
func CreateVirusReportEmbed(m *discordgo.MessageCreate, response VirusTotalResponse) *discordgo.MessageEmbed {
	embed := &discordgo.MessageEmbed{
		Description: "## <a:carregando:1163910534081552457> Ameaças foram encontradas!",
		Thumbnail: &discordgo.MessageEmbedThumbnail{
			URL: "https://i.imgur.com/5sTjkKy.gif",
		},
		Color: 0xFFFFFF, // Cor vermelha (personalize conforme necessário)
		Author: &discordgo.MessageEmbedAuthor{
			Name:    m.Author.Username,
			IconURL: m.Author.AvatarURL(""),
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%d de %d antivírus detectaram ameaças", response.Positives, response.Total),
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
		embed.Description = "## ✅ Nenhuma ameaça foi encontrada!"
		embed.Color = 0x00FF00

	}
	return embed
}
