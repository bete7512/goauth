package http_utils

import "net/http"

func SetCookie(w http.ResponseWriter, cookie *http.Cookie) {
	w.Header().Add("Set-Cookie", cookie.String())
}

func GetCookie(r *http.Request, name string) *http.Cookie {
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil
	}
	return cookie
}
