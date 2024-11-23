package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetBotToken() (string, error) {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err.Error())
		return "", fmt.Errorf("erro ao carregar o arquivo .env")
	}

	token := os.Getenv("BOT_TOKEN")
	if token == "" {
		return "", fmt.Errorf("token do bot não encontrado")
	}

	return token, nil
}

func GetVtToken() (string, error) {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err.Error())
		return "", fmt.Errorf("erro ao carregar o arquivo .env")
	}

	token := os.Getenv("VT_TOKEN")
	if token == "" {
		return "", fmt.Errorf("token do VirusTotal não encontrado")
	}

	return token, nil
}
