package satgo

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// buildCanonicalXML genera el nodo <des:solicitud> ordenando los atributos alfabéticamente de forma automática.
func buildCanonicalXML(atributos map[string]string, innerXML string) string {
	// 1. Extraer las llaves del mapa
	keys := make([]string, 0, len(atributos))
	for k := range atributos {
		keys = append(keys, k)
	}

	// 2. Ordenar alfabéticamente (Regla de oro del SAT)
	sort.Strings(keys)

	// 3. Construir la cadena de atributos dinámicamente
	var attrsBuilder strings.Builder
	for _, k := range keys {
		attrsBuilder.WriteString(fmt.Sprintf(` %s="%s"`, k, atributos[k]))
	}

	// 4. Ensamblar el nodo con o sin contenido interno
	if innerXML != "" {
		return fmt.Sprintf(`<des:solicitud%s>%s</des:solicitud>`, attrsBuilder.String(), innerXML)
	}
	return fmt.Sprintf(`<des:solicitud%s></des:solicitud>`, attrsBuilder.String())
}

// calculateDigest obtiene el hash SHA1 en base64 de una cadena
func calculateDigest(data string) string {
	hasher := sha1.New()
	hasher.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// buildSignedInfo es un helper extra para reciclar la plantilla XML del SignedInfo
func buildSignedInfo(digestValue string) string {
	return `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>` + digestValue + `</DigestValue></Reference></SignedInfo>`
}

// signRSA firma criptográficamente un texto usando la llave privada en memoria
func signRSA(privateKey *rsa.PrivateKey, data string) (string, error) {
	hasher := sha1.New()
	hasher.Write([]byte(data))
	hashedData := hasher.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashedData)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

// buildSoapEnvelope ensambla el XML final reemplazando el cierre de la solicitud con el bloque de firma
func buildSoapEnvelope(actionNode string, canonicalSolicitud string, signedInfo string, signatureValue string, certBase64 string, issuerName string, serialNumber string) string {

	// Plantilla de la firma
	signatureNode := fmt.Sprintf(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">%s<SignatureValue>%s</SignatureValue><KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>%s</X509IssuerName><X509SerialNumber>%s</X509SerialNumber></X509IssuerSerial><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></Signature>`,
		signedInfo, signatureValue, issuerName, serialNumber, certBase64)

	// Inyectamos la firma justo antes del cierre de </des:solicitud>
	solicitudConFirma := strings.Replace(canonicalSolicitud, "</des:solicitud>", signatureNode+"</des:solicitud>", 1)

	// Envolvemos todo en el cascarón SOAP apuntando al nodo de acción (ej. SolicitaDescargaFolio)
	soapBody := fmt.Sprintf(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><s:Header/><s:Body><des:%s>%s</des:%s></s:Body></s:Envelope>`,
		actionNode, solicitudConFirma, actionNode)

	return soapBody
}

func generarUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("uuid-%x-%x-%x-%x-%x-4", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (c *Client) enviarAutenticacion(soapBody string) (string, error) {
	url := "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(soapBody)))
	if err != nil {
		return "", fmt.Errorf("error creando request HTTP: %v", err)
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error en la petición al SAT: %v", err)
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)
	respuesta := string(bodyResp)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("el SAT respondió con status %d: %s", resp.StatusCode, respuesta)
	}

	// Extraer el token de la respuesta XML de forma sencilla
	// El SAT devuelve algo como: <AutenticaResult>TOKEN_STRING</AutenticaResult>
	startTag := `<AutenticaResult>`
	endTag := `</AutenticaResult>`

	inicio := strings.Index(respuesta, startTag)
	fin := strings.Index(respuesta, endTag)

	if inicio != -1 && fin != -1 {
		tokenPuro := respuesta[inicio+len(startTag) : fin]
		// El SAT requiere que mandemos el token con "WRAP access_token=" en los headers
		return fmt.Sprintf(`WRAP access_token="%s"`, tokenPuro), nil
	}

	return "", errors.New("no se pudo encontrar el AutenticaResult en la respuesta del SAT")
}

func enviarPeticionSAT(soapBody string) {
	url := "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(soapBody)))
	if err != nil {
		log.Fatalf("Error creando request HTTP: %v", err)
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica")

	client := &http.Client{Timeout: 15 * time.Second}

	fmt.Println("\nEnviando petición al SAT...")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error en la petición HTTP: %v", err)
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)

	fmt.Printf("Status HTTP: %s\n", resp.Status)
	fmt.Println("Respuesta del servidor:")
	fmt.Println(string(bodyResp))
}
