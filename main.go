package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
	e.GET("/callback", callbackHandler(cfg))

	// Restricted group
	r := e.Group("/*")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:  []byte(cfg.SharedSecret),
		TokenLookup: fmt.Sprintf("cookie:%s", cookieName),
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
		token := jwt.New(jwt.SigningMethodHS256)
		introspect, _, _ := iamClient.Introspect()

		user, _, err := iamClient.Users.GetUserByID(introspect.Sub)
		if err != nil {
			fmt.Printf("error getting user: %v\n", err)
		}

		// Set claims
		claims := token.Claims.(jwt.MapClaims)
		if introspect != nil {
			claims["username"] = introspect.Username
			claims["sub"] = introspect.Sub
		}
		if user != nil {
			claims["email"] = user.EmailAddress
			claims["name"] = fmt.Sprintf("%s %s", user.Name.Given, user.Name.Family)
		}
		claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
		claims["iam_access_token"] = iamClient.Token()
		claims["iam_refresh_token"] = iamClient.RefreshToken()

		// Generate encoded token and send it as response.
		t, err := token.SignedString([]byte(cfg.SharedSecret))
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
		return c.JSON(http.StatusOK, map[string]string{
			"token": t,
		})
	}
}
