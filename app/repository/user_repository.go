package repository

import (
	"context"
	"time"

	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/pkg/database"
)

func InsertNewUser(ctx context.Context, user *models.User) error {
	return database.DB.Create(user).Error
}

func InsertNewUserSession(ctx context.Context, user *models.UserSession) error {
	return database.DB.Create(user).Error
}

func GetUserSessionByToken(ctx context.Context, token string) (models.UserSession, error) {
	var (
		resp models.UserSession
		err  error
	)
	err = database.DB.Where("token = ?", token).Last(&resp).Error
	return resp, err
}

func UpdateUserSessionToken(ctx context.Context, token, refreshToken string, tokenExpired time.Time) error {
	return database.DB.Model(&models.UserSession{}).
		Where("refresh_token = ?", refreshToken).
		Updates(map[string]interface{}{
			"token":         token,
			"token_expired": tokenExpired,
			"updated_at":    time.Now(),
		}).Error
}

func DeleteUserSessionByToken(ctx context.Context, token string) error {
	return database.DB.Where("token = ?", token).Delete(&models.UserSession{}).Error
}

func GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	var (
		resp models.User
		err  error
	)
	err = database.DB.Where("username = ?", username).Last(&resp).Error
	return resp, err
}
