package filesutils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
)

// Estrutura que representa a resposta do VirusTotal após a verificação de um arquivo
type VirusTotalResponse struct {
	ResponseCode int `json:"response_code"`
	Positives    int `json:"positives"`
	Total        int `json:"total"`
	Scans        map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
	} `json:"scans"`
}

func DownloadFile(url, fileName string) string {
	// Faça o download do arquivo a partir de uma URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Printf("Erro ao baixar o arquivo: %v\n", err)
		return ""
	}
	defer response.Body.Close()

	filePath := fileName

	// Crie um arquivo local para salvar o arquivo baixado
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Erro ao criar o arquivo temporário: %v\n", err)
		return ""
	}
	defer file.Close()

	// Copie o conteúdo do arquivo baixado para o arquivo local
	_, err = io.Copy(file, response.Body)
	if err != nil {
		fmt.Printf("Erro ao salvar o arquivo temporário: %v\n", err)
		return ""
	}

	return filePath
}

func CheckVirus(filePath string) (VirusTotalResponse, error) {
	// Carrega as variaves de ambient .env
	if err := godotenv.Load(); err != nil {
		fmt.Println("Erro ao carregar o arquivo .env")
	}

	// Verifique o arquivo em busca de ameaças usando o VirusTotal
	virusTotalAPIKey := os.Getenv("VT_TOKEN")

	file, err := os.Open(filePath)
	if err != nil {
		return VirusTotalResponse{}, err
	}
	defer file.Close()

	// Calcule o hash SHA256 do arquivo
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	fileHash := hex.EncodeToString(hash.Sum(nil))

	client := resty.New()
	url := "https://www.virustotal.com/vtapi/v2/file/report"
	params := map[string]string{
		"apikey":   virusTotalAPIKey,
		"resource": fileHash,
	}

	resp, err := client.R().
		SetQueryParams(params).
		Get(url)

	if err != nil {
		return VirusTotalResponse{}, err
	}

	if resp.StatusCode() != http.StatusOK {
		return VirusTotalResponse{}, fmt.Errorf("Erro ao consultar o VirusTotal.")
	}

	var response VirusTotalResponse
	err = json.Unmarshal([]byte(resp.String()), &response)
	if err != nil {
		return VirusTotalResponse{}, fmt.Errorf("Erro ao analisar a resposta do VirusTotal.")
	}

	return response, nil
}
