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
	secure       bool
	domain       string
	callbackURL  string
	successURL   string
}

// FacebookProviderConfig configuration structure for FacebookAuthProvider
type FacebookProviderConfig struct {
	ClientID      string
	ClientSecret  string
	UserStorage   UserStorage
	SecureCookies bool
	Domain        string
	CallbackURL   string
	SuccessURL    string
}

// NewFacebookAuthProvider creates new auth provider using config structure
func NewFacebookAuthProvider(conf FacebookProviderConfig) *FacebookAuthProvider {
	return &FacebookAuthProvider{
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
		gocial:       gocialite.NewDispatcher(),
		gc:           gcache.New(20).LRU().Build(),
		us:           conf.UserStorage,
		secure:       conf.SecureCookies,
		domain:       conf.Domain,
		callbackURL:  conf.CallbackURL,
		successURL:   conf.SuccessURL,
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
	req = mh.fp.checkRequest(req)
	if req == nil {
		res.WriteHeader(401)
		res.Write([]byte("Request unauthorized"))
		return
	}
	mh.h.ServeHTTP(res, req)
}

// MiddlewareHandler for protected paths
func (fp *FacebookAuthProvider) MiddlewareHandler(h http.Handler) http.Handler {
	return fp.newMiddlewareHandler(h)
}

func (fp *FacebookAuthProvider) checkRequest(request *http.Request) *http.Request {
	token := request.Header.Get("token")
	if token == "" {
		tokenCookie, _ := request.Cookie("token")
		if tokenCookie != nil {
			token = tokenCookie.Value
		}
	}

	if token == "" {
		return nil
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
			return request.WithContext(ctx)
		}
	}

	id := fp.idByToken(token)
	if len(id) > 0 {
		user, err := fp.us.Find(id)
		if err != nil {
			return nil
		}

		if user != nil {
			err = fp.gc.SetWithExpire(token, id, time.Second*3600)
			if err != nil {
				return nil
			}

			ctx := context.WithValue(request.Context(), ctxUserID, id)
			return request.WithContext(ctx)
		}
	}
	return nil
}

// Middleware for protected paths
func (fp *FacebookAuthProvider) Middleware(f func(res http.ResponseWriter, req *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		request = fp.checkRequest(request)
		if request == nil {
			response.WriteHeader(401)
			response.Write([]byte("Request unauthorized"))
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
		Domain:   fp.domain,
		Path:     "/",
	})

	http.Redirect(w, r, fp.successURL, 301)
}

// HandleFacebook handles FB authorization
func (fp *FacebookAuthProvider) HandleFacebook(w http.ResponseWriter, r *http.Request) {
	log.Printf("Callback %v", fp.callbackURL)
	authURL, err := fp.gocial.New().
		Driver("facebook").        // Set provider
		Scopes([]string{"email"}). // Set optional scope(s)
		Redirect(                  //
			fp.clientID,     // Client ID
			fp.clientSecret, // Client Secret
			fp.callbackURL,  // Redirect URL
		)

	// Check for errors (usually driver not valid)
	if err != nil {
		w.Write([]byte("Error: " + err.Error()))
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}
