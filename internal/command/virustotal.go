package command

import (
	"fmt"
	"virustotal/internal/vt"

	"github.com/bwmarrin/discordgo"
)

func VirusTotal(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}

	commandData := i.ApplicationCommandData()
	commandName := commandData.Name

	switch commandName {
	case "virustotal":
		options := commandData.Options[0].Name

		if options != "arquivo" {
			return
		}

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Flags:   discordgo.MessageFlagsEphemeral,
				Content: "<a:loading:1226191600749777046> Processando",
			},
		})

		attachmentID := commandData.Options[0].Value.(string)
		attachment := commandData.Resolved.Attachments[attachmentID]
		attachmentUrl := attachment.URL
		attachmentName := attachment.Filename

		filePath := vt.DownloadFile(attachmentUrl, attachmentName)
		if filePath == "" {
			fmt.Println("Erro ao baixar o arquivo.")
			return
		}

		response, err := vt.CheckVirus(filePath)
		if err != nil {
			fmt.Printf("Erro ao verificar o arquivo com o VirusTotal: %v\n", err)
			return
		}

		var embed *discordgo.MessageEmbed
		if response.Positives > 0 {
			embed = vt.CreateVirusReportEmbed(s, i.Member.User, response, attachmentName)
		} else {
			embed = vt.CreateVirusReportMessage(s, i.Member.User, response, attachmentName)
		}

		content := ""
		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Content: &content,
			Embeds:  &[]*discordgo.MessageEmbed{embed},
		})

		s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Flags:   discordgo.MessageFlagsEphemeral,
			Content: "<:check:1225850599661375539> Verificação concluída com sucesso!",
		})
	}
}
