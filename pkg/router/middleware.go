package router

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"go.elastic.co/apm"
)

func MiddlewareValidateAuth(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "MiddlewareValidateAuth", "middleware")
	defer span.End()

	auth := ctx.Get("Authorization")
	if auth == "" {
		log.Println("authorization empty")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	_, err := repository.GetUserSessionByToken(spanCtx, auth)
	if err != nil {
		log.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	claim, err := jwt_token.ValidateToken(spanCtx, auth)
	if err != nil {
		log.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	if time.Now().Unix() > claim.ExpiresAt.Unix() {
		log.Println("jwt token is expiredL ", claim.ExpiresAt)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	ctx.Set("username", claim.Username)
	ctx.Set("fullname", claim.Fullname)

	return ctx.Next()
}

func MiddlewareRefreshToken(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "MiddlewareRefreshToken", "middleware")
	defer span.End()

	auth := ctx.Get("Authorization")
	if auth == "" {
		log.Println("authorization empty")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	claim, err := jwt_token.ValidateToken(spanCtx, auth)
	if err != nil {
		log.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	if time.Now().Unix() > claim.ExpiresAt.Unix() {
		log.Println("jwt token is expiredL ", claim.ExpiresAt)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "unauthorize", nil)
	}

	ctx.Locals("username", claim.Username)
	ctx.Locals("fullname", claim.Fullname)

	return ctx.Next()
}
