package satgo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/youmark/pkcs8"
)

type Credentials struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	RFC         string
}

type Client struct {
	credentials Credentials
	token       string
	expiresAt   time.Time
	HTTPClient  *http.Client
}

func newClient(cert *x509.Certificate, key *rsa.PrivateKey, rfc string) *Client {
	return &Client{
		credentials: Credentials{
			Certificate: cert,
			PrivateKey:  key,
			RFC:         rfc,
		},
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func NewClientFromPEM(certPEM, keyPEM []byte, rfc string) (*Client, error) {

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return newClient(cert, rsaKey, rfc), nil
}

func NewClientFromFiles(certPath, keyPath, password string, rfc string) (*Client, error) {

	certDER, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyDER, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := parseCertificateDER(certDER)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKeyDER(keyDER, password)
	if err != nil {
		return nil, err
	}

	return newClient(cert, key, rfc), nil
}

func parsePrivateKeyDER(data []byte, password string) (*rsa.PrivateKey, error) {

	key, err := pkcs8.ParsePKCS8PrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return rsaKey, nil
}

func parseCertificateDER(data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(data)
}

func (c *Client) RFC() string {
	return c.credentials.RFC
}

func (c *Client) Verificacion(IdSolicitud string, RfcSolicitante string) (string, error) {
	if err := c.authenticateIfNeeded(); err != nil {
		return "", err
	}
	return "", errors.New("función no implementada aún")
}

// SolicitarDescargaCFDI pide el paquete masivo
func (c *Client) Descarga(IdSolicitud string, RfcSolicitante string) (string, error) {
	if err := c.authenticateIfNeeded(); err != nil {
		return "", err
	}
	return "", errors.New("función no implementada aún")
}

func (c *Client) autenticar() (string, time.Time, error) {
	now := time.Now().UTC()
	created := now.Format("2006-01-02T15:04:05.000Z")
	expirestime := now.Add(5 * time.Minute)
	expires := expirestime.Format("2006-01-02T15:04:05.000Z")
	uuidStr := generarUUID()

	// 1. Crear el Timestamp Canonicalizado
	canonicalTimestamp := `<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_0">` +
		`<u:Created>` + created + `</u:Created>` +
		`<u:Expires>` + expires + `</u:Expires>` +
		`</u:Timestamp>`

	// Reciclamos el helper para calcular el hash del timestamp de forma limpia
	digestValue := calculateDigest(canonicalTimestamp)

	// 2. Crear el SignedInfo Canonicalizado para WSS
	canonicalSignedInfo := `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>` +
		`<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>` +
		`<Reference URI="#_0">` +
		`<Transforms>` +
		`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>` +
		`</Transforms>` +
		`<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>` +
		`<DigestValue>` + digestValue + `</DigestValue>` +
		`</Reference>` +
		`</SignedInfo>`

	// 3. Firmar usando nuestro nuevo método universal
	signatureValue, err := signRSA(c.credentials.PrivateKey, canonicalSignedInfo)
	if err != nil {
		return "", expirestime, fmt.Errorf("error firmando la solicitud de autenticación: %v", err)
	}

	certBase64 := base64.StdEncoding.EncodeToString(c.credentials.Certificate.Raw)

	// 4. Ensamblar la petición SOAP final
	soapRequest := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
		`<s:Header>` +
		`<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` +
		canonicalTimestamp +
		`<o:BinarySecurityToken u:Id="` + uuidStr + `" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` +
		certBase64 +
		`</o:BinarySecurityToken>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		canonicalSignedInfo +
		`<SignatureValue>` + signatureValue + `</SignatureValue>` +
		`<KeyInfo>` +
		`<o:SecurityTokenReference>` +
		`<o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#` + uuidStr + `" />` +
		`</o:SecurityTokenReference>` +
		`</KeyInfo>` +
		`</Signature>` +
		`</o:Security>` +
		`</s:Header>` +
		`<s:Body>` +
		`<Autentica xmlns="http://DescargaMasivaTerceros.gob.mx" />` +
		`</s:Body>` +
		`</s:Envelope>`
	token, err := c.enviarAutenticacion(soapRequest)

	return token, expirestime, err
}

// Fecha inicial (Obligatorio): Fecha de inicio, con formato AAAA-MM-DDThh:mm:ss.
// Fecha final (Obligatorio): Fecha de fin del rango, con formato AAAA-MM-DDThh:mm:ss.
// RFC Receptor (opcional): Contiene un arreglo de el/los RFCs receptores de los cuales se quiere consultar los CFDIs (Máximo 5).
// RFC Emisor (Obligatorio): Contiene el RFC del emisor del cual se quiere consultar los CFDI.
// RFC solicitante (Opcional): Contiene el RFC del que está realizando la solicitud de descarga. Este parámetro es opcional, pero en caso de proporcionarse debe coincidir con el RFC Emisor.
// Tipo de Solicitud (Obligatorio): Tipo de solicitud que se realizará al SAT, CFDI o Metadata.
// Tipo de Comprobante (Opcional): Define el tipo de comprobante (Null, I = Ingreso, E = Egreso, T= Traslado, N = Nomina, P = Pago). Null es el valor predeterminado y en caso de no declararse, se obtendrán todos los comprobantes sin importar el tipo comprobante.
// Estado del comprobante (Opcional): Define el estado del comprobante (Todos, Cancelado, Vigente). En caso de que no se proporcione, se considerara Vigente como valor por defecto.
// RFC A Cuenta de Terceros (Opcional): Contiene el RFC del a cuenta a tercero del cual se quiere consultar los CFDIs.
// Complemento (Opcional): Define el complemento de CFDI a descargar. null es el valor predeterminado y en caso de no declararse, se obtendrán todos los comprobantes sin importar el complemento asociado a los comprobantes.
func (c *Client) SolicitudEmitidos(uuid string, rfcSolicitante string, tipoSolicitud string, folio string) (string, error) {
	if err := c.authenticateIfNeeded(); err != nil {
		return "", err
	}
	// 1. Definir los atributos (El map en Go no tiene orden fijo, pero buildCanonicalXML lo ordenará)
	atributos := map[string]string{
		"RfcSolicitante": rfcSolicitante,
		"Folio":          uuid,
	}

	// 2. Generar el nodo canónico (Inner XML vacío porque Folio va como atributo ahora)
	nodoSolicitud := buildCanonicalXML(atributos, "")

	// 3. Preparar el string exacto para el Hash
	nodoParaHash := fmt.Sprintf(`<des:SolicitaDescargaFolio xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">%s</des:SolicitaDescargaFolio>`, nodoSolicitud)

	// 4. Calcular el Hash (DigestValue)
	digestValue := calculateDigest(nodoParaHash)

	// 5. Generar y firmar el SignedInfo
	signedInfo := buildSignedInfo(digestValue)
	signatureValue, err := signRSA(c.credentials.PrivateKey, signedInfo)
	if err != nil {
		return "", fmt.Errorf("error al firmar por folio: %v", err)
	}

	// 6. Obtener datos del certificado para el KeyInfo
	certBase64 := base64.StdEncoding.EncodeToString(c.credentials.Certificate.Raw)
	issuerName := c.credentials.Certificate.Issuer.String()
	serialNumber := c.credentials.Certificate.SerialNumber.String()

	// 7. Ensamblar SOAP final
	soapFinal := buildSoapEnvelope("SolicitaDescargaFolio", nodoSolicitud, signedInfo, signatureValue, certBase64, issuerName, serialNumber)

	// 8. Aquí enviarías la petición HTTP usando c.HTTPClient, c.Token y soapFinal...
	fmt.Println(soapFinal)
	urlSAT := "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
	soapAction := "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"

	respuestaXML, err := c.enviarPeticionNegocio(urlSAT, soapAction, soapFinal)
	if err != nil {
		return "", fmt.Errorf("error en la solicitud al SAT: %w", err)
	}
	return respuestaXML, nil
}

// Fecha inicial (Obligatorio): Fecha de inicio, con formato AAAA-MM-DDThh:mm:ss.
// Fecha final (Obligatorio): Fecha de fin del rango, con formato AAAA-MM-DDThh:mm:ss.
// RFC Receptor (Obligatorio): Contiene el RFC Receptor el cual corresponde con el contribuyente del cual se requiere la información.
// RFC Emisor (Opcional): Contiene el RFC del emisor del cual se quiere consultar los CFDI.
// RFC solicitante (Opcional): Contiene el RFC del que está realizando la solicitud de descarga. Este parámetro es opcional, pero en caso de proporcionarse debe coincidir con el RFC Receptor.
// Tipo de Comprobante (Opcional): Define el tipo de comprobante (Null, I = Ingreso, E = Egreso, T= Traslado, N = Nomina, P = Pago). Null es el valor predeterminado y en caso de no declararse, se obtendrán todos los comprobantes sin importar el tipo comprobante.
// Estado del comprobante (Opcional): Define el estado del comprobante (Todos, Cancelado, Vigente). En caso de que no se proporcione, se considerara Vigente como valor por defecto.
// REGLA: Para efectos de la metadata el listado solo incluirá los comprobantes vigentes y cancelados, para efectos de la descarga de XML, solo se incluirán los vigentes. Por lo tanto, el servicio no descargará XML cancelados.
// RFC A Cuenta de Terceros (Opcional): Contiene el RFC del a cuenta a tercero del cual se quiere consultar los CFDIs.
// Complemento (Opcional): Define el complemento de CFDI a descargar. null es el valor predeterminado y en caso de no declararse, se obtendrán todos los comprobantes sin importar el complemento asociado a los comprobantes.
func (c *Client) SolicitudRecibidos(fechaInicial string, fechaFinal string, tipoSolicitud string, rfcReceptor string) (string, error) {
	if err := c.authenticateIfNeeded(); err != nil {
		return "", err
	}
	// 1. Definir los atributos (El map en Go no tiene orden fijo, pero buildCanonicalXML lo ordenará)
	atributos := map[string]string{
		"EstadoComprobante": "Vigente",
		"FechaInicial":      fechaInicial,
		"FechaFinal":        fechaFinal,
		"RfcEmisor":         "",
		"RfcReceptor":       rfcReceptor,
		"RfcSolicitante":    rfcReceptor,
		"TipoSolicitud":     tipoSolicitud, // "CFDI" o "Metadata"
	}

	// 2. Generar el nodo canónico (Inner XML vacío porque Folio va como atributo ahora)
	nodoSolicitud := buildCanonicalXML(atributos, "")

	// 3. Preparar el string exacto para el Hash
	nodoParaHash := fmt.Sprintf(`<des:SolicitaDescargaRecibidos xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">%s</des:SolicitaDescargaRecibidos>`, nodoSolicitud)

	// 4. Digest + Firma
	digestValue := calculateDigest(nodoParaHash)
	signedInfo := buildSignedInfo(digestValue)
	signatureValue, err := signRSA(c.credentials.PrivateKey, signedInfo)
	if err != nil {
		return "", fmt.Errorf("error al firmar solicitud recibidos: %w", err)
	}

	// 5. Obtener datos del certificado para el KeyInfo
	certBase64 := base64.StdEncoding.EncodeToString(c.credentials.Certificate.Raw)
	issuerName := c.credentials.Certificate.Issuer.String()
	serialNumber := c.credentials.Certificate.SerialNumber.String()

	// 6. Ensamblar SOAP final
	soapFinal := buildSoapEnvelope("SolicitaDescargaRecibidos", nodoSolicitud, signedInfo, signatureValue, certBase64, issuerName, serialNumber)

	// 8. Aquí enviarías la petición HTTP usando c.HTTPClient, c.Token y soapFinal...
	// (Queda pendiente crear el helper enviarPeticionNegocio)
	fmt.Println(soapFinal)

	urlSAT := "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
	soapAction := "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos"

	respuestaXML, err := c.enviarPeticionNegocio(urlSAT, soapAction, soapFinal)
	if err != nil {
		return "", fmt.Errorf("error en la solicitud al SAT: %w", err)
	}

	return respuestaXML, nil
}

// RFC solicitante (Opcional), Folio (Obligatorio)
func (c *Client) SolicitudFolio(rfcSolicitante string, folio string) (string, error) {
	if err := c.authenticateIfNeeded(); err != nil {
		return "", err
	}
	atributos := map[string]string{
		"RfcSolicitante": c.credentials.RFC,
		"Folio":          folio,
	}
	nodoSolicitud := buildCanonicalXML(atributos, "")
	nodoParaHash := fmt.Sprintf(`<des:SolicitaDescargaFolio xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">%s</des:SolicitaDescargaFolio>`, nodoSolicitud)
	digestValue := calculateDigest(nodoParaHash)
	signedInfo := buildSignedInfo(digestValue)
	signatureValue, err := signRSA(c.credentials.PrivateKey, signedInfo)
	if err != nil {
		return "", fmt.Errorf("error al firmar por folio: %v", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(c.credentials.Certificate.Raw)
	issuerName := c.credentials.Certificate.Issuer.String()
	serialNumber := c.credentials.Certificate.SerialNumber.String()
	soapFinal := buildSoapEnvelope("SolicitaDescargaFolio", nodoSolicitud, signedInfo, signatureValue, certBase64, issuerName, serialNumber)
	//fmt.Println(soapFinal)
	urlSAT := "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
	soapAction := "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaFolio"
	respuestaXML, err := c.enviarPeticionNegocio(urlSAT, soapAction, soapFinal)
	if err != nil {
		return "", fmt.Errorf("error en la solicitud al SAT: %w", err)
	}
	return respuestaXML, nil
}

func (c *Client) authenticateIfNeeded() error {
	if c.token != "" && time.Now().Add(10*time.Second).Before(c.expiresAt) {
		return nil
	}

	token, expiresAt, err := c.autenticar()

	if err != nil {
		return fmt.Errorf("fallo al renovar el token del SAT: %w", err)
	}

	c.token = token
	c.expiresAt = expiresAt
	return nil
}
