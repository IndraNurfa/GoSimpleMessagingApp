package repository

import (
	"context"
	"time"

	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/pkg/database"
	"go.elastic.co/apm"
)

func InsertNewUser(ctx context.Context, user *models.User) error {
	span, _ := apm.StartSpan(ctx, "InsertNewUser", "repository")
	defer span.End()

	return database.DB.Create(user).Error
}

func InsertNewUserSession(ctx context.Context, user *models.UserSession) error {
	span, _ := apm.StartSpan(ctx, "InsertNewUserSession", "repository")
	defer span.End()

	return database.DB.Create(user).Error
}

func GetUserSessionByToken(ctx context.Context, token string) (models.UserSession, error) {
	span, _ := apm.StartSpan(ctx, "GetUserSessionByToken", "repository")
	defer span.End()
	
	var (
		resp models.UserSession
		err  error
	)
	err = database.DB.Where("token = ?", token).Last(&resp).Error
	return resp, err
}

func UpdateUserSessionToken(ctx context.Context, token, refreshToken string, tokenExpired time.Time) error {
	span, _ := apm.StartSpan(ctx, "UpdateUserSessionToken", "repository")
	defer span.End()
	
	return database.DB.Model(&models.UserSession{}).
		Where("refresh_token = ?", refreshToken).
		Updates(map[string]interface{}{
			"token":         token,
			"token_expired": tokenExpired,
			"updated_at":    time.Now(),
		}).Error
}

func DeleteUserSessionByToken(ctx context.Context, token string) error {
	span, _ := apm.StartSpan(ctx, "DeleteUserSessionByToken", "repository")
	defer span.End()

	return database.DB.Where("token = ?", token).Delete(&models.UserSession{}).Error
}

func GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	span, _ := apm.StartSpan(ctx, "GetUserByUsername", "repository")
	defer span.End()

	var (
		resp models.User
		err  error
	)

	err = database.DB.Where("username = ?", username).Last(&resp).Error
	return resp, err
}
