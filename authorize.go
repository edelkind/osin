package osin

import (
    "errors"
    "net/http"
    "net/url"
    "regexp"
    "time"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string

const (
    CODE          AuthorizeRequestType = "code"
    TOKEN                              = "token"
    IDTOKEN                            = "id_token"
    TOKEN_IDTOKEN                      = "token id_token"
)

var MatchOpenId = regexp.MustCompile(`(^|\s+)openid(\s+|$)`)

// Authorize request information
type AuthorizeRequest struct {
    Type        AuthorizeRequestType
    Client      *Client
    Scope       string
    RedirectUri string
    State       string

    // Set if request is authorized
    Authorized bool

    // Will be true if the request is an OpenID Connect request.
    IsOpenId bool

    // Data useful for generating the OpenID Connect id_token.
    IdTokenData *IdTokenData

    // Token expiration in seconds. Change if different from default.
    // If type = TOKEN, this expiration will be for the ACCESS token.
    Expiration int32

    // Key for JWT signatures
    SigningKey []byte

    // Data to be passed to storage. Not used by the library.
    UserData interface{}
}

// Authorization data
type AuthorizeData struct {
    // Client information
    Client *Client

    // Authorization code
    Code string

    // Token expiration in seconds
    ExpiresIn int32

    // Requested scope
    Scope string

    // Redirect Uri from request
    RedirectUri string

    // State data from request
    State string

    // Date created
    CreatedAt time.Time

    // OpenID Connect id_token source data
    IdTokenData *IdTokenData

    // OpenID Connect id_token (only set if the request is openid)
    IdToken string

    // Key for JWT signatures
    SigningKey []byte

    // Data to be passed to storage. Not used by the library.
    UserData interface{}
}

// IsExpired is true if authorization expired
func (d *AuthorizeData) IsExpired() bool {
    return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second).Before(time.Now())
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
    return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface
type AuthorizeTokenGen interface {
    GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// AuthorizeTokenGen is the token generator interface
type IdTokenGen interface {
    GenerateIdToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
    r.ParseForm()

    requestType := AuthorizeRequestType(r.Form.Get("response_type"))
    if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
        switch requestType {
        case CODE:
            return s.handleCodeRequest(w, r)
        case TOKEN:
            return s.handleTokenRequest(w, r)
        case IDTOKEN:
            return s.handleIdTokenRequest(w, r)
        case TOKEN_IDTOKEN:
            return s.handleTokenIdTokenRequest(w, r)
        }
    }

    w.SetError(E_UNSUPPORTED_RESPONSE_TYPE, "")
    return nil
}

func (s *Server) handleCommon(w *Response, r *http.Request) *AuthorizeRequest {
    return nil
}

func (s *Server) handleCodeRequest(w *Response, r *http.Request) *AuthorizeRequest {
    // create the authorization request
    unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
    if err != nil {
        unescapedUri = ""
    }
    scope := r.Form.Get("scope")
    ret := &AuthorizeRequest{
        Type:        CODE,
        State:       r.Form.Get("state"),
        Scope:       scope,
        RedirectUri: unescapedUri,
        Authorized:  false,
        IsOpenId:    MatchOpenId.MatchString(scope),
        Expiration:  s.Config.AuthorizationExpiration,
    }

    // must have a valid client
    ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
    if err != nil {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = err
        return nil
    }
    if ret.Client == nil {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }
    if ret.Client.RedirectUri == "" {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }

    // force redirect response to client redirecturl first
    w.SetRedirect(ret.Client.RedirectUri)

    // check redirect uri
    if ret.RedirectUri == "" {
        ret.RedirectUri = ret.Client.RedirectUri
    }
    if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
        w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
        w.InternalError = err
        return nil
    }

    return ret
}

func (s *Server) handleIdTokenRequest(w *Response, r *http.Request) *AuthorizeRequest {
    // create the authorization request
    unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
    if err != nil {
        unescapedUri = ""
    }

    scope := r.Form.Get("scope")
    ret := &AuthorizeRequest{
        Type:        IDTOKEN,
        State:       r.Form.Get("state"),
        Scope:       scope,
        RedirectUri: unescapedUri,
        Authorized:  false,
        IsOpenId:    MatchOpenId.MatchString(scope),
        Expiration:  s.Config.AuthorizationExpiration,
    }

    // must have a valid client
    ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
    if err != nil {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = err
        return nil
    }
    if ret.Client == nil {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }
    if ret.Client.RedirectUri == "" {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }

    // must be an openid request
    if !ret.IsOpenId {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = errors.New("expected openid in scope")
        return nil
    }

    // force redirect response to client redirecturl first
    w.SetRedirect(ret.Client.RedirectUri)

    // check redirect uri
    if ret.RedirectUri == "" {
        ret.RedirectUri = ret.Client.RedirectUri
    }
    if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
        w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
        w.InternalError = err
        return nil
    }

    return ret
}

func (s *Server) handleTokenIdTokenRequest(w *Response, r *http.Request) *AuthorizeRequest {
    // create the authorization request
    unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
    if err != nil {
        unescapedUri = ""
    }

    scope := r.Form.Get("scope")
    ret := &AuthorizeRequest{
        Type:        TOKEN_IDTOKEN,
        State:       r.Form.Get("state"),
        Scope:       scope,
        RedirectUri: unescapedUri,
        Authorized:  false,
        IsOpenId:    MatchOpenId.MatchString(scope),
        Expiration:  s.Config.AuthorizationExpiration,
    }

    // must have a valid client
    ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
    if err != nil {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = err
        return nil
    }
    if ret.Client == nil {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }
    if ret.Client.RedirectUri == "" {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }

    // must be an openid request
    if !ret.IsOpenId {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = errors.New("expected openid in scope")
        return nil
    }

    // force redirect response to client redirecturl first
    w.SetRedirect(ret.Client.RedirectUri)

    // check redirect uri
    if ret.RedirectUri == "" {
        ret.RedirectUri = ret.Client.RedirectUri
    }
    if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
        w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
        w.InternalError = err
        return nil
    }

    return ret
}

func (s *Server) handleTokenRequest(w *Response, r *http.Request) *AuthorizeRequest {
    // create the authorization request
    unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
    if err != nil {
        unescapedUri = ""
    }

    scope := r.Form.Get("scope")
    ret := &AuthorizeRequest{
        Type:        TOKEN,
        State:       r.Form.Get("state"),
        Scope:       scope,
        RedirectUri: unescapedUri,
        Authorized:  false,
        IsOpenId:    MatchOpenId.MatchString(scope),
        // this type will generate a token directly, use access token expiration instead.
        Expiration: s.Config.AccessExpiration,
    }

    // must have a valid client
    ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
    if err != nil {
        w.SetErrorState(E_SERVER_ERROR, "", ret.State)
        w.InternalError = err
        return nil
    }
    if ret.Client == nil {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }
    if ret.Client.RedirectUri == "" {
        w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
        return nil
    }

    // force redirect response to client redirecturl first
    w.SetRedirect(ret.Client.RedirectUri)

    // check redirect uri
    if ret.RedirectUri == "" {
        ret.RedirectUri = ret.Client.RedirectUri
    }
    if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
        w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
        w.InternalError = err
        return nil
    }

    return ret
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
    // don't process if is already an error
    if w.IsError {
        return
    }

    // force redirect response
    w.SetRedirect(ar.RedirectUri)

    if ar.Authorized {
        if ar.Type == TOKEN { // XXX: || TOKEN_IDTOKEN?
            w.SetRedirectFragment(true)

            // generate token directly
            ret := &AccessRequest{
                Type:            IMPLICIT,
                Code:            "",
                Client:          ar.Client,
                RedirectUri:     ar.RedirectUri,
                Scope:           ar.Scope,
                GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
                Authorized:      true,
                Expiration:      ar.Expiration,
                UserData:        ar.UserData,
            }

            s.FinishAccessRequest(w, r, ret)
        }
        if ar.Type == IDTOKEN || ar.Type == CODE || ar.Type == TOKEN_IDTOKEN {
            // generate authorization token
            ret := &AuthorizeData{
                Client:      ar.Client,
                CreatedAt:   time.Now(),
                ExpiresIn:   ar.Expiration,
                RedirectUri: ar.RedirectUri,
                State:       ar.State,
                Scope:       ar.Scope,
                UserData:    ar.UserData,
                IdTokenData: ar.IdTokenData,
                SigningKey:  ar.SigningKey,
            }

            if ar.IsOpenId && ret.IdTokenData == nil {
                w.SetErrorState(E_SERVER_ERROR, "", ar.State)
                w.InternalError = errors.New("OpenID Connect request made, but IdTokenData is not set")
                return
            }

            // generate token code
            code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
            if err != nil {
                w.SetErrorState(E_SERVER_ERROR, "", ar.State)
                w.InternalError = err
                return
            }
            ret.Code = code

            if ret.IdTokenData != nil {

                if err := PopulateIdToken(r, ret.IdTokenData); err != nil {
                    w.SetErrorState(E_SERVER_ERROR, "", ar.State)
                    w.InternalError = err
                    return
                }

                err := GenerateIdToken(ret)
                if err != nil {
                    w.SetErrorState(E_SERVER_ERROR, "", ar.State)
                    w.InternalError = err
                    return
                }

            }

            // save authorization token
            if err = s.Storage.SaveAuthorize(ret); err != nil {
                w.SetErrorState(E_SERVER_ERROR, "", ar.State)
                w.InternalError = err
                return
            }

            // redirect with code
            w.Output["code"] = ret.Code
            w.Output["state"] = ret.State
        }
    } else {
        // redirect with error
        w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
    }
}
