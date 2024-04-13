package vt

import (
	"fmt"
	"strings"
	"virustotal/internal/models"

	"github.com/bwmarrin/discordgo"
)

func CreateVirusReportEmbed(s *discordgo.Session, user *discordgo.User, response models.VirusTotalResponse, fileName string) *discordgo.MessageEmbed {
	embed := &discordgo.MessageEmbed{
		Thumbnail: &discordgo.MessageEmbedThumbnail{
			URL: "https://i.imgur.com/V4LNILY.png",
		},
		Author: &discordgo.MessageEmbedAuthor{
			Name: fileName,
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%d de %d antivírus detectaram ameaças", response.Positives, response.Total),
		},
		Description: formatThreats(response),
	}

	if embed.Description == "" {
		embed.Description = "<:check:1225850599661375539> Nenhuma ameaça foi encontrada!"
		embed.Color = 0x00FF00
	} else {
		embed.Color = 0xFF0000
	}

	return embed
}

func CreateVirusReportMessage(s *discordgo.Session, user *discordgo.User, response models.VirusTotalResponse, fileName string) *discordgo.MessageEmbed {
	return CreateVirusReportEmbed(s, user, response, fileName)
}

func formatThreats(response models.VirusTotalResponse) string {
	var threats []string
	for scan, result := range response.Scans {
		if result.Detected {
			threats = append(threats, fmt.Sprintf("**<:servidor:1228841081337151499> Antivírus:** %s\n**<:Erro:1228840827283968000> Ameaça:** ``%s``", scan, result.Result))
		}
	}
	return strings.Join(threats, "\n\n")
}
