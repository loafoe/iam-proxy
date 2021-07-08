package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/philips-software/go-hsdp-api/config"
	"github.com/philips-software/go-hsdp-api/iam"
	"github.com/spf13/viper"
)

type appConfig struct {
	APPURL       string
	UpstreamURL  string
	Environment  string
	Region       string
	SharedSecret string
	CookieDomain string
	ClientID     string
	ClientSecret string
	Port         string
	RedirectURI  string
	LoginURI     string
	PrivateKey   *rsa.PrivateKey
}

const (
	cookieName = "IAMProxy"
)

func main() {
	// Config gathering
	viper.SetEnvPrefix("iam_proxy")
	viper.AutomaticEnv()

	viper.SetDefault("app_url", "http://localhost:35444")
	viper.SetDefault("region", "us-east")
	viper.SetDefault("environment", "client-test")
	viper.SetDefault("shared_secret", "secret")
	viper.SetDefault("private_key_base64", "")
	viper.SetDefault("cookie_domain", "")
	viper.SetDefault("upstream_url", "")
	viper.SetDefault("port", "35444")

	cfg := appConfig{
		APPURL:       viper.GetString("app_url"),
		UpstreamURL:  viper.GetString("upstream_url"),
		Port:         viper.GetString("port"),
		Region:       viper.GetString("region"),
		Environment:  viper.GetString("environment"),
		ClientID:     viper.GetString("client_id"),
		ClientSecret: viper.GetString("client_secret"),
		SharedSecret: viper.GetString("shared_secret"),
		CookieDomain: viper.GetString("cookie_domain"),
	}
	pemData, err := base64.StdEncoding.DecodeString(viper.GetString("private_key_base64"))
	if err != nil {
		fmt.Printf("private_key_base64 is invalid or empty\n")
		return
	}
	cfg.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(pemData)
	if err != nil {
		fmt.Printf("invalid private_key: %v\n", err)
		return
	}
	if cfg.CookieDomain == "" {
		app, _ := url.Parse(cfg.APPURL)
		cfg.CookieDomain = app.Host
	}
	if cfg.UpstreamURL == "" {
		fmt.Printf("upstream_url is required.\n")
		return
	}
	cfg.RedirectURI = cfg.APPURL + "/callback"
	cfg.LoginURI = cfg.APPURL + "/login"

	// Echo
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	// IAM flow handling
	e.GET("/login", loginHandler(cfg))
	e.GET("/.well-known/jwks.json", wellKnownHandler(cfg))
	e.GET("/callback", callbackHandler(cfg))

	// Restricted group
	r := e.Group("/*")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:    cfg.PrivateKey.Public(),
		SigningMethod: "RS256",
		TokenLookup:   fmt.Sprintf("cookie:%s", cookieName),
		ErrorHandlerWithContext: func(err error, c echo.Context) error {
			return c.Redirect(http.StatusTemporaryRedirect, cfg.LoginURI+"?error="+err.Error())
		},
		SuccessHandler: func(c echo.Context) {
			cookie, err := c.Cookie(cookieName)
			if err != nil {
				_ = c.JSON(http.StatusForbidden, "missing cookie")
				return
			}
			c.Request().Header.Set("X-JWT-Assertion", cookie.Value)
		},
	}))

	// Reverse proxy
	origin, _ := url.Parse(cfg.UpstreamURL)
	targets := []*middleware.ProxyTarget{
		{
			URL: origin,
		},
	}
	r.Use(middleware.ProxyWithConfig(middleware.ProxyConfig{
		Balancer:  middleware.NewRandomBalancer(targets),
		Transport: newVirtualHostRoundTripper(http.DefaultTransport, origin.Host),
	}))

	// Go go go!
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}

type Keys struct {
	Keys []jwk.Key `json:"keys"`
}

func keyIDEncode(b []byte) string {
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf bytes.Buffer
	var i int
	for i = 0; i < len(s)/4-1; i++ {
		start := i * 4
		end := start + 4
		buf.WriteString(s[start:end] + ":")
	}
	buf.WriteString(s[i*4:])
	return buf.String()
}

func keyIDFromCryptoKey(pubKey crypto.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	hasher := crypto.SHA256.New()
	hasher.Write(derBytes)
	return keyIDEncode(hasher.Sum(nil)[:30])
}

func wellKnownHandler(cfg appConfig) echo.HandlerFunc {
	key, _ := jwk.New(cfg.PrivateKey.Public())
	publicKey := cfg.PrivateKey.Public()

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Minute * 86400 * 90)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	keyUsage := x509.KeyUsageDigitalSignature
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, cfg.PrivateKey)
	if err != nil {
		fmt.Printf("ERROR CREATING DER......\n")
	}
	str := base64.StdEncoding.EncodeToString(derBytes)
	fmt.Printf("x5c: [%s]\n", str)

	if key != nil {
		_ = key.Set("use", "sig")
		_ = key.Set("alg", "RS256")
		_ = key.Set("kid", keyIDFromCryptoKey(cfg.PrivateKey.Public()))
		_ = key.Set(jwk.X509CertChainKey, []string{str})
	}

	return func(c echo.Context) error {
		if key == nil {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		return c.JSON(http.StatusOK, Keys{
			Keys: []jwk.Key{key},
		})
	}
}

type virtualHostRoundTripper struct {
	next http.RoundTripper
	Host string
}

func newVirtualHostRoundTripper(next http.RoundTripper, host string) *virtualHostRoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &virtualHostRoundTripper{
		next: next,
		Host: host,
	}
}

func (rt *virtualHostRoundTripper) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if rt.Host != "" {
		req.Host = rt.Host
	}
	return rt.next.RoundTrip(req)
}

func loginHandler(cfg appConfig) echo.HandlerFunc {
	hsdpConfig, _ := config.New(config.WithRegion(cfg.Region), config.WithEnv(cfg.Environment))

	return func(c echo.Context) error {
		baseIAMURL := hsdpConfig.Service("iam").URL
		redirectURL := baseIAMURL + fmt.Sprintf("/authorize/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s", cfg.ClientID, cfg.RedirectURI)
		return c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	}
}

func callbackHandler(cfg appConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		iamClient, _ := iam.NewClient(nil, &iam.Config{
			OAuth2ClientID: cfg.ClientID,
			OAuth2Secret:   cfg.ClientSecret,
			Region:         cfg.Region,
			Environment:    cfg.Environment,
		})
		code := c.QueryParam("code")
		err := iamClient.CodeLogin(code, cfg.RedirectURI)
		if err != nil {
			_ = c.HTML(http.StatusForbidden, "<html><body>Login failed</body></html>")
			return err
		}
		// Create token
		token := jwt.New(jwt.SigningMethodRS256)
		introspect, _, _ := iamClient.Introspect()

		user, _, err := iamClient.Users.GetUserByID(introspect.Sub)
		if err != nil {
			fmt.Printf("error getting user: %v\n", err)
		}
		token.Header["kid"] = keyIDFromCryptoKey(cfg.PrivateKey.Public())

		// Set claims
		claims := token.Claims.(jwt.MapClaims)
		if introspect != nil {
			claims["username"] = introspect.Username
			claims["sub"] = introspect.Sub
		}
		if user != nil {
			claims["email"] = user.EmailAddress
			claims["name"] = fmt.Sprintf("%s %s", user.Name.Given, user.Name.Family)
			claims["given_name"] = user.Name.Given
			claims["family_name"] = user.Name.Family
		}
		claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
		claims["iam_access_token"] = iamClient.Token()
		claims["iam_refresh_token"] = iamClient.RefreshToken()
		claims["aud"] = cfg.ClientID
		//claims["iss"] = fmt.Sprintf("https://%s", cfg.CookieDomain)

		// Generate encoded token and send it as response.
		t, err := token.SignedString(cfg.PrivateKey)
		if err != nil {
			return err
		}
		// Set Cookie
		c.SetCookie(&http.Cookie{
			Name:     cookieName,
			Value:    t,
			Path:     "/",
			Domain:   cfg.CookieDomain,
			HttpOnly: true,
		})
		return c.Redirect(http.StatusFound, "/")
	}
}
