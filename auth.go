// Package auth handles Facebook authentication
package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/bluele/gcache"
	"github.com/danilopolani/gocialite"
)

type contextKey int

const (
	ctxUserID contextKey = iota
)

// UserStorage stores user data. Coulbe be implemented using any DB or ORM
type UserStorage interface {
	Save(user map[string]interface{}) error
	Find(fbid string) (map[string]interface{}, error)
}

// FacebookAuthProvider main structure handling Facebook authentication
type FacebookAuthProvider struct {
	clientID     string
	clientSecret string
	gocial       *gocialite.Dispatcher
	gc           gcache.Cache
	us           UserStorage
	conf         FacebookProviderConfig
}

// FacebookProviderConfig configuration structure for FacebookAuthProvider
type FacebookProviderConfig struct {
	ClientID      string
	ClientSecret  string
	SecureCookies bool
	Domain        string
	CallbackURL   string
	SuccessURL    string
	FailURL       string
}

// NewFacebookAuthProvider creates new auth provider using config structure
func NewFacebookAuthProvider(conf FacebookProviderConfig, us UserStorage) *FacebookAuthProvider {
	return &FacebookAuthProvider{
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
		gocial:       gocialite.NewDispatcher(),
		gc:           gcache.New(20).LRU().Build(),
		conf:         conf,
		us:           us,
	}
}

// UserIDbyCtx retrieves autheticated user ID from net/http context
func UserIDbyCtx(ctx context.Context) string {
	if val, ok := ctx.Value(ctxUserID).(string); ok {
		return val
	}
	return ""
}

func (fp *FacebookAuthProvider) idByToken(token string) string {
	resp, err := http.Get("https://graph.facebook.com/me?access_token=" + token)
	//resp, err := http.Get("https://graph.facebook.com/oauth/access_token_info?client_id=" + fp.clientId + "&access_token=" + token)
	if err != nil {
		log.Printf("Token verification. Error sending request: %v", err)
		return ""
	}

	defer resp.Body.Close()
	var m map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		log.Printf("Token verification. Error decoding JSON: %v", err)
		return ""
	}
	if errorInterface, hasError := m["error"]; hasError {
		errorMap := errorInterface.(map[string]interface{})
		if errorMsg, hasMsg := errorMap["message"]; hasMsg {
			log.Printf("Token verification error: %v", errorMsg)
		}
		return ""
	}

	if id, ok := m["id"]; ok {
		if idString, ok := id.(string); ok {
			return idString
		}

	}

	return ""
}

type middlewareHandler struct {
	h  http.Handler
	fp *FacebookAuthProvider
}

func (fp *FacebookAuthProvider) newMiddlewareHandler(h http.Handler) *middlewareHandler {
	return &middlewareHandler{
		h,
		fp,
	}
}
func (mh *middlewareHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if !mh.fp.checkRequest(req) {
		if mh.fp.conf.FailURL == "" {
			res.WriteHeader(401)
			res.Write([]byte("Request unauthorized"))
		} else {
			http.Redirect(res, req, mh.fp.conf.FailURL, 302)
		}
		return
	}
	mh.h.ServeHTTP(res, req)
}

// MiddlewareHandler for protected paths
func (fp *FacebookAuthProvider) MiddlewareHandler(h http.Handler) http.Handler {
	return fp.newMiddlewareHandler(h)
}

func (fp *FacebookAuthProvider) checkRequest(request *http.Request) bool {
	token := request.Header.Get("token")
	if token == "" {
		tokenCookie, _ := request.Cookie("token")
		if tokenCookie != nil {
			token = tokenCookie.Value
		}
	}

	if token == "" {
		return false
	}

	idString, err := fp.gc.GetIFPresent(token)
	if err != nil {
		if gcache.KeyNotFoundError != err {
			log.Printf("Error accessing cache: %v", err)
		}
	}

	if id, ok := idString.(string); ok {
		if len(id) > 0 {
			ctx := context.WithValue(request.Context(), ctxUserID, id)
			*request = *(request.WithContext(ctx))
		}
	}

	id := fp.idByToken(token)
	if len(id) > 0 {
		user, err := fp.us.Find(id)
		if err != nil {
			return false
		}

		if user != nil {
			err = fp.gc.SetWithExpire(token, id, time.Second*3600)
			if err != nil {
				return false
			}

			ctx := context.WithValue(request.Context(), ctxUserID, id)
			*request = *(request.WithContext(ctx))
			return true
		}
	}
	return false
}

// Middleware for protected paths
func (fp *FacebookAuthProvider) Middleware(f func(res http.ResponseWriter, req *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		if !fp.checkRequest(request) {
			if fp.conf.FailURL == "" {
				response.WriteHeader(401)
				response.Write([]byte("Request unauthorized"))
			} else {
				http.Redirect(response, request, fp.conf.FailURL, 302)
			}
			return
		}
		f(response, request)
	}
}

// HandleFacebookCallback handles FB callback
func (fp *FacebookAuthProvider) HandleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	user, token, err := fp.gocial.Handle(state, code)
	if err != nil {
		w.Write([]byte("Error: " + err.Error()))
		return
	}

	err = fp.us.Save(user.Raw)
	if err != nil {
		log.Printf("Unable to save user: %v", err)
		return
	}

	err = fp.gc.SetWithExpire(token, user.ID, time.Second*3600)
	if err != nil {
		log.Printf("Unable to cache user data: %v", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token.AccessToken,
		Secure:   false,
		HttpOnly: false,
		Domain:   fp.conf.Domain,
		Path:     "/",
	})

	http.Redirect(w, r, fp.conf.SuccessURL, 301)
}

// HandleFacebook handles FB authorization
func (fp *FacebookAuthProvider) HandleFacebook(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Add("Expires", "0")

	authURL, err := fp.gocial.New().
		Driver("facebook").        // Set provider
		Scopes([]string{"email"}). // Set optional scope(s)
		Redirect(                  //
			fp.clientID,         // Client ID
			fp.clientSecret,     // Client Secret
			fp.conf.CallbackURL, // Redirect URL
		)

	// Check for errors (usually driver not valid)
	if err != nil {
		w.Write([]byte("Error: " + err.Error()))
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}
