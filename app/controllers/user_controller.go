package controllers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"golang.org/x/crypto/bcrypt"
)

func Register(ctx *fiber.Ctx) error {
	user := new(models.User)

	err := ctx.BodyParser(user)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err = user.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		errResponse := fmt.Errorf("failed to encrypt password:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	user.Password = string(hashPass)

	err = repository.InsertNewUser(ctx.Context(), user)
	if err != nil {
		errResponse := fmt.Errorf("failed to insert new user:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	resp := user
	resp.Password = ""

	return response.SendSuccessResponse(ctx, resp)
}

func Login(ctx *fiber.Ctx) error {
	var (
		LoginReq = new(models.LoginRequest)
		resp     models.LoginResponse
		now      = time.Now()
	)

	err := ctx.BodyParser(LoginReq)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err = LoginReq.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	user, err := repository.GetUserByUsername(ctx.Context(), LoginReq.Username)
	if err != nil {
		errResponse := fmt.Errorf("failed to get username:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(LoginReq.Password))
	if err != nil {
		errResponse := fmt.Errorf("failed to check password:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "username/passsword salah", nil)
	}

	token, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate jwt token:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}

	refresh_token, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "refresh_token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate jwt refresh token:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}

	userSession := &models.UserSession{
		UserID:              int(user.ID),
		Token:               token,
		RefreshToken:        refresh_token,
		TokenExpired:        now.Add(jwt_token.MapTypeToken["token"]),
		RefreshTokenExpired: now.Add(jwt_token.MapTypeToken["refresh_token"]),
	}

	err = repository.InsertNewUserSession(ctx.Context(), userSession)
	if err != nil {
		errResponse := fmt.Errorf("failed to insert session:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}

	resp = models.LoginResponse{
		Username:     user.Username,
		Fullname:     user.Fullname,
		Token:        token,
		RefreshToken: refresh_token,
	}

	return response.SendSuccessResponse(ctx, resp)
}

func Logout(ctx *fiber.Ctx) error {
	token := ctx.Get("Authorization")
	err := repository.DeleteUserSessionByToken(ctx.Context(), token)
	if err != nil {
		errResponse := fmt.Errorf("failed delete user session:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}
	return response.SendSuccessResponse(ctx, nil)
}

func RefreshToken(ctx *fiber.Ctx) error {
	now := time.Now()
	refreshToken := ctx.Get("Authorization")
	username := ctx.Locals("username").(string)
	fullname := ctx.Locals("fullname").(string)

	token, err := jwt_token.GenerateToken(ctx.Context(), username, fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate jwt token:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}

	err = repository.UpdateUserSessionToken(ctx.Context(), token, refreshToken, now.Add(jwt_token.MapTypeToken["token"]))
	if err != nil {
		errResponse := fmt.Errorf("failed to update token:: %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan sistem", nil)
	}

	return response.SendSuccessResponse(ctx, fiber.Map{"token": token})
}
