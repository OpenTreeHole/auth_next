package apis

type EmailModel struct {
	// email in email blacklist
	Email string `json:"email"`
}

type LoginRequest struct {
	EmailModel
	Password string `json:"password" minLength:"8"`
}

type TokenResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	LoginRequest
	Verification string `json:"verification" minLength:"6" maxLength:"6"`
}

type EmailVerifyResponse struct {
	Message string `json:"message"`
	Scope   string `json:"scope" enums:"register,reset"`
}

type ApikeyRequest struct {
	EmailModel
	Apikey        string `json:"apikey"`
	CheckRegister bool   `json:"check_register" default:"false"` // if true, return whether registered
}

type ApikeyResponse struct {
	EmailVerifyResponse
	Code string `json:"code"`
}
