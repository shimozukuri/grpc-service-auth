package jwt_test

import (
	"grpc-service/internal/domain/models"
	jwtlib "grpc-service/internal/lib/jwt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestNewToken_Success(t *testing.T) {
	const (
		secret   = "test-secret"
		duration = time.Hour
	)

	user := models.User{
		ID:    1,
		Email: "test@example.com",
	}

	app := models.App{
		ID:     2,
		Secret: secret,
	}

	before := time.Now()

	tokenString, err := jwtlib.NewToken(
		user,
		app,
		duration,
	)

	after := time.Now()

	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
	)

	require.NoError(t, err)
	require.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	require.Equal(
		t,
		user.ID,
		int64(claims["uid"].(float64)),
	)

	require.Equal(
		t,
		user.Email,
		claims["email"],
	)

	require.Equal(
		t,
		app.ID,
		int(claims["app_id"].(float64)),
	)

	exp := int64(claims["exp"].(float64))

	require.GreaterOrEqual(
		t,
		exp,
		before.Add(duration).Unix(),
	)

	require.LessOrEqual(
		t,
		exp,
		after.Add(duration).Unix(),
	)
}

func TestNewToken_WrongSecret(t *testing.T) {
	user := models.User{
		ID:    1,
		Email: "test@example.com",
	}

	app := models.App{
		ID:     1,
		Secret: "correct-secret",
	}

	tokenString, err := jwtlib.NewToken(
		user,
		app,
		time.Hour,
	)
	require.NoError(t, err)

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return []byte("wrong-secret"), nil
		},
	)

	require.Error(t, err)
	require.False(t, token.Valid)
}
