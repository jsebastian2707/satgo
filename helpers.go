package satgo

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

func buildCanonicalXML(nodeName string, atributos map[string]string, innerXML string) string {
	keys := make([]string, 0, len(atributos))
	for k := range atributos {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var attrsBuilder strings.Builder
	for _, k := range keys {
		attrsBuilder.WriteString(fmt.Sprintf(` %s="%s"`, k, atributos[k]))
	}

	if innerXML != "" {
		return fmt.Sprintf(`<%s%s>%s</%s>`, nodeName, attrsBuilder.String(), innerXML, nodeName)
	}
	return fmt.Sprintf(`<%s%s></%s>`, nodeName, attrsBuilder.String(), nodeName)
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

func buildSoapEnvelope(actionNode string, canonicalSolicitud string, nodeName string, signedInfo string, signatureValue string, certBase64 string, issuerName string, serialNumber string) string {
	signatureNode := fmt.Sprintf(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">%s<SignatureValue>%s</SignatureValue><KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>%s</X509IssuerName><X509SerialNumber>%s</X509SerialNumber></X509IssuerSerial><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></Signature>`,
		signedInfo, signatureValue, issuerName, serialNumber, certBase64)

	// Ahora reemplaza el cierre correcto dinámicamente
	cierreNodo := fmt.Sprintf(`</%s>`, nodeName)
	solicitudConFirma := strings.Replace(canonicalSolicitud, cierreNodo, signatureNode+cierreNodo, 1)

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

	startTag := `<AutenticaResult>`
	endTag := `</AutenticaResult>`

	inicio := strings.Index(respuesta, startTag)
	fin := strings.Index(respuesta, endTag)

	if inicio != -1 && fin != -1 {
		tokenPuro := respuesta[inicio+len(startTag) : fin]
		return fmt.Sprintf(`WRAP access_token="%s"`, tokenPuro), nil
	}

	return "", errors.New("no se pudo encontrar el AutenticaResult en la respuesta del SAT")
}

func (c *Client) enviarPeticionNegocio(url string, soapAction string, soapBody string) (string, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(soapBody)))
	if err != nil {
		return "", fmt.Errorf("error creando request: %v", err)
	}

	// Headers estándar + El Token de autorización que se generó automáticamente
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", soapAction)
	req.Header.Set("Authorization", c.token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error enviando la petición: %v", err)
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error HTTP %d del SAT: %s", resp.StatusCode, string(bodyResp))
	}

	return string(bodyResp), nil
}

func (c *Client) enviarPeticionDescarga(soapBody string) (string, error) {
	req, err := http.NewRequest("POST", "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc", bytes.NewBuffer([]byte(soapBody)))
	if err != nil {
		return "", fmt.Errorf("error creando request: %v", err)
	}

	// Headers estándar + El Token de autorización que se generó automáticamente
	req.Header.Set("Accept-Encoding", "gzip,deflate")
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar")
	req.Header.Set("Authorization", c.token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error enviando la petición: %v", err)
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error HTTP %d del SAT: %s", resp.StatusCode, string(bodyResp))
	}

	return string(bodyResp), nil
}

//xml

type RespuestaSolicitud struct {
	IdSolicitud    string `json:"id_solicitud"`
	RfcSolicitante string `json:"rfc_solicitante"`
	CodEstatus     string `json:"cod_estatus"`
	Mensaje        string `json:"mensaje"`
}

// --- ESTRUCTURAS XML MEJORADAS ---
type soapEnvelopeSolicitud struct {
	XMLName xml.Name          `xml:"Envelope"`
	Body    soapBodySolicitud `xml:"Body"`
}

type soapBodySolicitud struct {
	// Ahora atrapa la respuesta de cualquiera de los 3 métodos
	RecibidosResult *resultadoSolicitudNode `xml:"SolicitaDescargaRecibidosResponse>SolicitaDescargaRecibidosResult"`
	EmitidosResult  *resultadoSolicitudNode `xml:"SolicitaDescargaResponse>SolicitaDescargaResult"`
	FolioResult     *resultadoSolicitudNode `xml:"SolicitaDescargaFolioResponse>SolicitaDescargaFolioResult"`
}

type resultadoSolicitudNode struct {
	IdSolicitud    string `xml:"IdSolicitud,attr"`
	RfcSolicitante string `xml:"RfcSolicitante,attr"`
	CodEstatus     string `xml:"CodEstatus,attr"`
	Mensaje        string `xml:"Mensaje,attr"`
}

// HELPER UNIVERSAL PARA SOLICITUDES
func parseRespuestaSolicitud(xmlData string) (*RespuestaSolicitud, error) {
	var envelope soapEnvelopeSolicitud
	if err := xml.Unmarshal([]byte(xmlData), &envelope); err != nil {
		return nil, err
	}

	var nodo *resultadoSolicitudNode
	if envelope.Body.RecibidosResult != nil {
		nodo = envelope.Body.RecibidosResult
	} else if envelope.Body.EmitidosResult != nil {
		nodo = envelope.Body.EmitidosResult
	} else if envelope.Body.FolioResult != nil {
		nodo = envelope.Body.FolioResult
	}

	if nodo == nil {
		return nil, errors.New("no se encontró el nodo de resultado en la respuesta XML de Solicitud")
	}

	return &RespuestaSolicitud{
		IdSolicitud:    nodo.IdSolicitud,
		RfcSolicitante: nodo.RfcSolicitante,
		CodEstatus:     nodo.CodEstatus,
		Mensaje:        nodo.Mensaje,
	}, nil
}

//verificacion

type RespuestaVerificacion struct {
	CodEstatus            string   `json:"cod_estatus"`
	EstadoSolicitud       string   `json:"estado_solicitud"`
	CodigoEstadoSolicitud string   `json:"codigo_estado_solicitud"`
	NumeroCFDIs           string   `json:"numero_cfdis"`
	Mensaje               string   `json:"mensaje"`
	IdsPaquetes           []string `json:"ids_paquetes"`
}

// --- ESTRUCTURAS XML ---
type soapEnvelopeVerificacion struct {
	XMLName xml.Name             `xml:"Envelope"`
	Body    soapBodyVerificacion `xml:"Body"`
}

type soapBodyVerificacion struct {
	Result *resultadoVerificacionNode `xml:"VerificaSolicitudDescargaResponse>VerificaSolicitudDescargaResult"`
}

type resultadoVerificacionNode struct {
	CodEstatus            string   `xml:"CodEstatus,attr"`
	EstadoSolicitud       string   `xml:"EstadoSolicitud,attr"`
	CodigoEstadoSolicitud string   `xml:"CodigoEstadoSolicitud,attr"`
	NumeroCFDIs           string   `xml:"NumeroCFDIs,attr"`
	Mensaje               string   `xml:"Mensaje,attr"`
	IdsPaquetes           []string `xml:"IdsPaquetes>string"` // Extrae cada <string>ID</string>
}

func parseRespuestaVerificacion(xmlData string) (*RespuestaVerificacion, error) {
	var envelope soapEnvelopeVerificacion
	if err := xml.Unmarshal([]byte(xmlData), &envelope); err != nil {
		return nil, err
	}

	nodo := envelope.Body.Result
	if nodo == nil {
		return nil, errors.New("no se encontró el nodo de resultado en la respuesta XML de Verificación")
	}

	return &RespuestaVerificacion{
		CodEstatus:            nodo.CodEstatus,
		EstadoSolicitud:       nodo.EstadoSolicitud,
		CodigoEstadoSolicitud: nodo.CodigoEstadoSolicitud,
		NumeroCFDIs:           nodo.NumeroCFDIs,
		Mensaje:               nodo.Mensaje,
		IdsPaquetes:           nodo.IdsPaquetes,
	}, nil
}

//descarga

// --- OBJETO LIMPIO PARA TU APP ---
type RespuestaDescarga struct {
	CodEstatus string `json:"cod_estatus"`
	Mensaje    string `json:"mensaje"`
	PaqueteB64 string `json:"paquete_b64"` // String gigante en Base64 del .zip
}

// --- ESTRUCTURAS XML ---
type soapEnvelopeDescarga struct {
	XMLName xml.Name           `xml:"Envelope"`
	Header  soapHeaderDescarga `xml:"Header"`
	Body    soapBodyDescarga   `xml:"Body"`
}

type soapHeaderDescarga struct {
	Respuesta *headerRespuestaDescarga `xml:"respuesta"`
}

type headerRespuestaDescarga struct {
	CodEstatus string `xml:"CodEstatus,attr"`
	Mensaje    string `xml:"Mensaje,attr"`
}

type soapBodyDescarga struct {
	Paquete string `xml:"RespuestaDescargaMasivaTercerosSalida>Paquete"`
}

// HELPER
func parseRespuestaDescarga(xmlData string) (*RespuestaDescarga, error) {
	var envelope soapEnvelopeDescarga
	if err := xml.Unmarshal([]byte(xmlData), &envelope); err != nil {
		return nil, err
	}

	// El SAT a veces omite el Header si ocurre un error grave en la petición
	estatus := ""
	mensaje := ""
	if envelope.Header.Respuesta != nil {
		estatus = envelope.Header.Respuesta.CodEstatus
		mensaje = envelope.Header.Respuesta.Mensaje
	}

	// Si no viene paquete (ej. error 5000) el string será vacío
	paquete := envelope.Body.Paquete

	if estatus == "" && paquete == "" {
		return nil, errors.New("no se pudo parsear ni el header ni el paquete de descarga")
	}

	return &RespuestaDescarga{
		CodEstatus: estatus,
		Mensaje:    mensaje,
		PaqueteB64: paquete,
	}, nil
}
