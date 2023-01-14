package account

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password" minLength:"8"`
}

type LoginResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Message string `json:"message"`
}
