// Package forsooth provides a dropin Oauth2 handler for  gogle logins
package forsooth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const oauthGoogleAPIcall = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

var sessionCookieName = "defaultSessionCookie"

// Forsooth is the config object for the funcs
type Forsooth struct {
	ClientID     string         `yaml:"client_id"`
	ClientSecret string         `yaml:"client_secret"`
	RedirectURL  string         `yaml:"redirect_url"`
	Scopes       []string       `yaml:"scopes"`
	Conf         *oauth2.Config `yaml:-`
}

func (f *Forsooth) LoadConfig(r *io.Reader) {

}

// Authorizations need to be indicated for users to see firewall, door and other sections

//ServeHTTP makes OauthLogin a http.Handler
func (l OauthLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// fetch session
	ses, c, err := getSessionCookie(r)
	if ses == nil {
		// bad cookie
		if err != nil {
			log.Printf("Error getting auth cookie:%v\n", err)
		}

		//try to reauth session
		oauthGoogleLogin(w, r)
	}
	// ok if we get here we have a good session
	//log.Printf("Session cookie:%#v\n", *c)

	////set cookie
	//if l.Cookie.MaxAge < c.MaxAge {
	//	c.MaxAge = l.Cookie.MaxAge
	//}
	// preserve cookie in the return
	setAuthSessionCookie(w, c, ses)
	// make sure downstream finds the session cookie if they need it
	// r.AddCookie(c)
	l.NextHandler.ServeHTTP(w, r)
}

// RandomString produces a base64 string (websafe?) from n random bytes
func RandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("RandomString: Not Enough Random %v", err)
	}
	s := base64.RawStdEncoding.EncodeToString(b)
	return s
}

// extra?  Here's a "go home func"
func oauthRedirect(w http.ResponseWriter, r *http.Request) {

	HomeHandler(w, r)
}

// OAuthGoogleLogin does the google login redirect.
func oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState URL, session and session cookie
	// get a unique state/sessionid

	state := RandomString(64)
	_, found := activeSessions.Find(state)
	for found {
		state = RandomString(64)
		_, found = activeSessions.Find(state)

	}
	session := ActiveSession{
		SessionID: state,
		State:     RandomString(64),
		Expires:   time.Now().Add(time.Minute * 3),
	}
	setAuthSessionCookie(w, nil, &session)
	activeSessions.Add(&session)

	u := oauth2.googleOauthConfig.AuthCodeURL(session.SessionID)
	r.Header.Set("accept", "application/json")

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// OauthLogin type for oauth handler
type OauthLogin struct {
	NextHandler http.Handler
}

// NewLoginHandler generates a login middleware
func NewLoginHandler(next http.Handler) OauthLogin {
	h := OauthLogin{
		NextHandler: next,
	}
	return h
}

// NewLogoutHandler generates a login middleware
func NewLogoutHandler(next http.Handler) OauthLogin {
	h := OauthLogin{
		NextHandler: next,
	}
	return h
}
func getSessionCookie(r *http.Request) (*ActiveSession, *http.Cookie, error) {
	c, err := r.Cookie(sessionCookieName)
	// fetch session
	var ses *ActiveSession
	if err == nil && c != nil {
		ses = &ActiveSession{}

		err = json.Unmarshal([]byte(c.Value), &ses)
		// trust just the session id
		if err == nil {
			s, found := activeSessions.Find(ses.SessionID)
			if !found {
				return nil, c, fmt.Errorf("session not found")
			}
			// TODO compare for warning
			ses = s
		}
	}
	//there was an error, or no cookie, or test session expire
	if err != nil || c == nil || time.Since(ses.Expires) >= 0 {
		// bad cookie,no session
		ses = nil
		if err != nil {
			log.Printf("Error getting auth cookie:%v\n", err)
		}

	}
	return ses, c, err
}

func setAuthSessionCookie(w http.ResponseWriter, c *http.Cookie, s *ActiveSession) error {
	if s == nil {
		return fmt.Errorf("Attempted to set Nil Session")
	}

	b, err := json.Marshal(s)
	if err != nil {
		//error encoding session?
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if c == nil {
		c = &http.Cookie{Name: sessionCookieName, Value: string(b), Expires: s.Expires,
			Domain: "batcave.jerman.info", Path: "/"}
	}
	c.Value = string(b)

	http.SetCookie(w, c)

	return nil
}

// GoogleLogin sends us here with a form to catch the userinfo
func oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	ses, c, err := getSessionCookie(r)
	if ses == nil {
		// bad cookie
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	}
	if r.FormValue("state") != ses.State {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Printf("Auth Content: %#v\n", string(data))

	u := GoogleUserProfile{}
	okUser := false
	err = json.Unmarshal(data, &u)
	if err != nil {
		for _, au := range cfg.Oauth2.Access {
			if au.GoogleID == u.ID {
				okUser = true
			}
			log.Printf("Compare:%v : %v\n", au.GoogleID, u.ID)
		}
		if okUser {
			ses.Token = string(data) // it's already json for u{}
			ses.User = u
			// pass the cookie on the w side
			activeSessions.Add(ses)
			setAuthSessionCookie(w, c, ses)

			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
	}
	// clear cookie and be logged out if we get here without login
	oauthLogout(w, r)
}

func oauthLogout(w http.ResponseWriter, r *http.Request) {
	ses, c, err := getSessionCookie(r)
	if err != nil {
		log.Println(err.Error())
	} else {
		c = &http.Cookie{
			Name:   sessionCookieName,
			Value:  "",
			Domain: "batcave.jerman.info",
			Path:   "/",
			MaxAge: -1,
		}
		http.SetCookie(w, c)
		log.Println("logout")
	}
	if ses != nil {
		activeSessions.Delete(ses.SessionID)
	}
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusTemporaryRedirect)
}
func getUserDataFromGoogle(code string) ([]byte, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleAPIcall + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}
	return contents, nil
}

//GetSession returns the logged in user or cleans up if youve expired
func GetSession(w http.ResponseWriter, r *http.Request) *ActiveSession {
	ses, c, err := getSessionCookie(r)
	if err != nil {
		log.Printf("Error foo getting auth cookie:%v\n", err)
	} else {
		log.Printf("cookie:%#v\n", *c)

		if err != nil {
			log.Printf("Error bar getting auth cookie:%v\n", err)
		}
	}
	if ses == nil {
		ses = &ActiveSession{} //safe refs
	}
	return ses
}

//GoogleUserProfile catches user data
type GoogleUserProfile struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	ID       string `json:"id"`
	Picture  string `json:"picture"`
}

// ActiveSession to serialize and track valid tokens
type ActiveSession struct {
	SessionID string            `json:"sessionid"`
	User      GoogleUserProfile `json:"auth_user"`
	Token     string            `json:"token"`
	State     string            `json:"state"`
	Expires   time.Time         `json:"exipires"`
}
type sessionStore struct {
	active map[string]ActiveSession
}

// wrapped map session store for RAM sessions
// TODO make this a db or cache with db backing

// Find (id) finds the active session with the id string
func (ss *sessionStore) Find(id string) (*ActiveSession, bool) {
	s, ok := ss.active[id]
	return &s, ok
}

// Add (ses) saves the  sessiom
func (ss *sessionStore) Add(s *ActiveSession) {
	if s != nil {
		ss.active[s.SessionID] = *s
	}
}

// Delete (id) drops the  sessiom
func (ss *sessionStore) Delete(id string) {
	delete(ss.active, id)

}

var activeSessions sessionStore
