package vt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"virustotal/internal/config"
	"virustotal/internal/models"

	"github.com/go-resty/resty/v2"
)

func DownloadFile(url, fileName string) string {
	filePath := fmt.Sprintf("./downloads/%s", fileName)
	out, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Erro ao criar o arquivo: %v\n", err)
		return ""
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Erro ao baixar o arquivo: %v\n", err)
		return ""
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		fmt.Printf("Erro ao salvar o arquivo: %v\n", err)
		return ""
	}

	return filePath
}

func CheckVirus(filePath string) (models.VirusTotalResponse, error) {
	virusTotalAPIKey, err := config.GetVtToken()
	if err != nil {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao obter chave API do VirusTotal: %v", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao abrir o arquivo: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao calcular hash do arquivo: %v", err)
	}

	fileHash := hex.EncodeToString(hash.Sum(nil))

	client := resty.New()
	url := "https://www.virustotal.com/vtapi/v2/file/report"
	params := map[string]string{
		"apikey":   virusTotalAPIKey,
		"resource": fileHash,
	}

	resp, err := client.R().SetQueryParams(params).Get(url)
	if err != nil {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao fazer a requisição para o VirusTotal: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao obter resposta válida do VirusTotal")
	}

	var response models.VirusTotalResponse
	err = json.Unmarshal([]byte(resp.String()), &response)
	if err != nil {
		return models.VirusTotalResponse{}, fmt.Errorf("erro ao analisar a resposta do VirusTotal: %v", err)
	}

	return response, nil
}
