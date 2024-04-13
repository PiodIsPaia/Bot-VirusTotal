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
		return "", fmt.Errorf(err.Error())
	}

	token := os.Getenv("TOKEN")

	return token, nil
}

func GetVtToken() (string, error) {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err.Error())
		return "", fmt.Errorf(err.Error())
	}

	token := os.Getenv("VT_TOKEN")

	return token, nil
}
