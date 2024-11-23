package bot

import (
	"log"
	"virustotal/internal/command"
	"virustotal/internal/config"

	"github.com/bwmarrin/discordgo"
)

var commands = &discordgo.ApplicationCommand{
	Name:        "virustotal",
	Description: "Verifique algum arquivo suspeito.",
	Type:        discordgo.ChatApplicationCommand,
	Options: []*discordgo.ApplicationCommandOption{
		{
			Name:        "arquivo",
			Description: "Coloque o arquivo aqui.",
			Type:        discordgo.ApplicationCommandOptionAttachment,
			Required:    true,
		},
	},
}

func Run() {
	token, err := config.GetBotToken()
	if err != nil {
		log.Fatal(err.Error())
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	dg.AddHandler(command.VirusTotal)
	dg.AddHandler(ready)

	if err := dg.Open(); err != nil {
		log.Fatal(err.Error())
		return
	}

	dg.ApplicationCommandCreate(dg.State.User.ID, "", commands)

	defer dg.Close()

	select {}
}

func ready(s *discordgo.Session, r *discordgo.Ready) {
	user, err := s.User("@me")
	if err != nil {
		log.Println(err.Error())
		return
	}

	log.Printf("%s is ready!", user.Username)
}
