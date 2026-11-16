package ui

import "github.com/bete7512/goauth/pkg/models"

func adminUser() *models.User { return &models.User{ID: "admin", IsSuperAdmin: true, Active: true} }
func plainUser() *models.User { return &models.User{ID: "plain", Active: true} }
