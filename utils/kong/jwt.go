package kong

//func CreateToken(user *models.User) (accessToken, refreshToken string, err error) {
//
//	jwtCredential, err := GetJwtCredential(user.ID)
//	if err != nil {
//		return "", "", err
//	}
//	claim := jwt.MapClaims{
//		"uid":         user.ID,
//		"iss":         jwtCredential.Key,
//		"iat":         time.Now().Unix(),
//		"id":          user.ID,
//		"nickname":    user.Nickname,
//		"joined_time": user.JoinedTime.Format(time.RFC3339),
//		"is_admin":    user.IsAdmin,
//	}
//
//	// access payload
//	claim["type"] = "access"
//	claim["exp"] = time.Now().Add(30 * time.Minute).Unix() // 30 minutes
//	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(jwtCredential.Secret))
//	if err != nil {
//		return "", "", err
//	}
//
//	// refresh payload
//	claim["type"] = "refresh"
//	claim["exp"] = time.Now().Add(30 * 24 * time.Hour).Unix() // 30 days
//	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(jwtCredential.Secret))
//	if err != nil {
//		return "", "", err
//	}
//
//	return
//}
