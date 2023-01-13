package apis

import "github.com/gofiber/fiber/v2"

type Info struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Homepage    string `json:"homepage"`
	Repository  string `json:"repository"`
	Author      string `json:"author"`
	Email       string `json:"email"`
	License     string `json:"license"`
}

// Index
// @Produce application/json
// @Success 200 {object} Info
// @Router / [get]
func Index(c *fiber.Ctx) error {
	return c.JSON(Info{
		Name:        "Open Tree Hole Auth",
		Description: "Next Generation of Auth microservice integrated with kong for registration and issuing tokens",
		Version:     "2.0",
		Homepage:    "https://github.com/opentreehole",
		Repository:  "https://github.com/OpenTreeHole/auth_next",
		Author:      "JingYiJun",
		Email:       "dev@fduhole.com",
		License:     "Apache-2.0",
	})
}
