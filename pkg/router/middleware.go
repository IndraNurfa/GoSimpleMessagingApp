package router

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
)

func MiddlewareValidateAuth(ctx *fiber.Ctx) error {
	auth := ctx.Get("Authorization")
	if auth == "" {
		fmt.Println("authorization empty")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	_, err := repository.GetUserSessionByToken(ctx.Context(), auth)
	if err != nil {
		fmt.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	claim, err := jwt_token.ValidateToken(ctx.Context(), auth)
	if err != nil {
		fmt.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	if time.Now().Unix() > claim.ExpiresAt.Unix() {
		fmt.Println("jwt token is expiredL ", claim.ExpiresAt)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	ctx.Set("username", claim.Username)
	ctx.Set("fullname", claim.Fullname)

	return ctx.Next()
}

func MiddlewareRefreshToken(ctx *fiber.Ctx) error {
	auth := ctx.Get("Authorization")
	if auth == "" {
		fmt.Println("authorization empty")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	claim, err := jwt_token.ValidateToken(ctx.Context(), auth)
	if err != nil {
		fmt.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	if time.Now().Unix() > claim.ExpiresAt.Unix() {
		fmt.Println("jwt token is expiredL ", claim.ExpiresAt)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	ctx.Locals("username", claim.Username)
	ctx.Locals("fullname", claim.Fullname)

	return ctx.Next()
}