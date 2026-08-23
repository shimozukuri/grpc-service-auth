package tests

import (
	"grpc-service/tests/suite"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	grpcservicev1 "github.com/shimozukuri/grpc-service-protos/gen/go/grpc-service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	invalidAppID = 999999
	emptyID      = 0
	appID        = 1
	appSecret    = "test-secret"

	passDefaultLen = 10
)

func TestAuth_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	userID := respReg.GetUserId()

	respLogin, err := st.AuthClient.Login(ctx, &grpcservicev1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)
	require.True(t, tokenParsed.Valid)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, userID, int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(
		t,
		loginTime.Add(st.Cfg.TokenTTL).Unix(),
		claims["exp"].(float64),
		deltaSeconds,
	)

	_, err = st.AuthClient.GrantAdmin(ctx, &grpcservicev1.GrantAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)

	respIsAdm, err := st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)
	assert.True(t, respIsAdm.IsAdmin)

	_, err = st.AuthClient.RevokeAdmin(ctx, &grpcservicev1.RevokeAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)

	respIsAdm, err = st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)
	assert.False(t, respIsAdm.IsAdmin)
}

func TestRegister_DuplicateRegister(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.Error(t, err)
	require.Empty(t, respReg.GetUserId())

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.AlreadyExists, statusErr.Code())
	assert.Equal(t, "user already exists", statusErr.Message())
}

func TestRegister_FailCases(t *testing.T) {
	testCases := []struct {
		name            string
		email           string
		password        string
		expectedCode    codes.Code
		expectedMessage string
	}{
		{
			name:            "empty password",
			email:           gofakeit.Email(),
			password:        "",
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "password required",
		},
		{
			name:            "empty email",
			email:           "",
			password:        randomFakePassword(),
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "email required",
		},
		{
			name:            "empty request",
			email:           "",
			password:        "",
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "email required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, st := suite.New(t)

			respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
				Email:    tc.email,
				Password: tc.password,
			})
			require.Error(t, err)
			require.Empty(t, respReg.GetUserId())

			statusErr, ok := status.FromError(err)
			require.True(t, ok)

			assert.Equal(t, tc.expectedCode, statusErr.Code())
			assert.Equal(t, tc.expectedMessage, statusErr.Message())
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	testCases := []struct {
		name            string
		email           string
		password        string
		appID           int32
		expectedCode    codes.Code
		expectedMessage string
	}{
		{
			name:            "empty password",
			email:           gofakeit.Email(),
			password:        "",
			appID:           appID,
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "password required",
		},
		{
			name:            "empty email",
			email:           "",
			password:        randomFakePassword(),
			appID:           appID,
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "email required",
		},
		{
			name:            "empty appID",
			email:           gofakeit.Email(),
			password:        randomFakePassword(),
			appID:           emptyID,
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "app_id required",
		},
		{
			name:            "empty request",
			email:           "",
			password:        "",
			appID:           emptyID,
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "email required",
		},
		{
			name:            "invalid credentials",
			email:           gofakeit.Email(),
			password:        randomFakePassword(),
			appID:           appID,
			expectedCode:    codes.InvalidArgument,
			expectedMessage: "invalid credentials",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, st := suite.New(t)

			respLogin, err := st.AuthClient.Login(ctx, &grpcservicev1.LoginRequest{
				Email:    tc.email,
				Password: tc.password,
				AppId:    tc.appID,
			})
			require.Error(t, err)
			require.Empty(t, respLogin.GetToken())

			statusErr, ok := status.FromError(err)
			require.True(t, ok)

			assert.Equal(t, tc.expectedCode, statusErr.Code())
			assert.Equal(t, tc.expectedMessage, statusErr.Message())
		})
	}
}

func TestRegisterLogin_Login_InvalidPassword(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()

	_, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: randomFakePassword(),
	})
	require.NoError(t, err)

	respLogin, err := st.AuthClient.Login(ctx, &grpcservicev1.LoginRequest{
		Email:    email,
		Password: randomFakePassword(),
		AppId:    appID,
	})
	require.Error(t, err)
	require.Empty(t, respLogin.GetToken())

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
	assert.Contains(t, statusErr.Message(), "invalid credentials")
}

func TestRegisterLogin_Login_InvalidApp(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)

	respLogin, err := st.AuthClient.Login(ctx, &grpcservicev1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    invalidAppID,
	})
	require.Error(t, err)
	require.Empty(t, respLogin.GetToken())

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
	assert.Equal(t, "invalid credentials", statusErr.Message())
}

func TestRegisterLogin_Login_TokenInvalidWithWrongSecret(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)

	respLogin, err := st.AuthClient.Login(ctx, &grpcservicev1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetToken())

	_, err = jwt.Parse(respLogin.GetToken(), func(token *jwt.Token) (interface{}, error) {
		return []byte("wrong-secret"), nil
	})
	require.Error(t, err)
}

func TestRegisterIsAdmin_IsAdmin_UserNotIsAdmin(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respIsAdm, err := st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: respReg.GetUserId(),
	})
	require.NoError(t, err)
	require.False(t, respIsAdm.GetIsAdmin())
}

func TestRegisterGrantAdminIsAdmin_IsAdmin_UserIsAdmin(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	userID := respReg.GetUserId()

	_, err = st.AuthClient.GrantAdmin(ctx, &grpcservicev1.GrantAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)

	respIsAdm, err := st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)
	require.True(t, respIsAdm.GetIsAdmin())
}

func TestIsAdmin_EmptyUserId(t *testing.T) {
	ctx, st := suite.New(t)

	respIsAdm, err := st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: emptyID,
	})
	require.Error(t, err)
	require.Empty(t, respIsAdm.GetIsAdmin())

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
	assert.Equal(t, "user_id required", statusErr.Message())
}

func TestIsAdmin_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    gofakeit.Email(),
		Password: randomFakePassword(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	userID := respReg.GetUserId() + 1

	respIsAdm, err := st.AuthClient.IsAdmin(ctx, &grpcservicev1.IsAdminRequest{
		UserId: userID,
	})
	require.Error(t, err)
	require.Empty(t, respIsAdm.GetIsAdmin())

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.NotFound, statusErr.Code())
	assert.Equal(t, "user not found", statusErr.Message())
}

func TestGrantAdmin_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    gofakeit.Email(),
		Password: randomFakePassword(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	userID := respReg.GetUserId() + 1

	_, err = st.AuthClient.GrantAdmin(ctx, &grpcservicev1.GrantAdminRequest{
		UserId: userID,
	})
	require.Error(t, err)

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.NotFound, statusErr.Code())
	assert.Equal(t, "user not found", statusErr.Message())
}

func TestGrantAdmin_EmptyUserId(t *testing.T) {
	ctx, st := suite.New(t)

	_, err := st.AuthClient.GrantAdmin(ctx, &grpcservicev1.GrantAdminRequest{
		UserId: emptyID,
	})
	require.Error(t, err)

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
	assert.Equal(t, "user_id required", statusErr.Message())
}

func TestRevokeAdmin_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	respReg, err := st.AuthClient.Register(ctx, &grpcservicev1.RegisterRequest{
		Email:    gofakeit.Email(),
		Password: randomFakePassword(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	userID := respReg.GetUserId() + 1

	_, err = st.AuthClient.RevokeAdmin(ctx, &grpcservicev1.RevokeAdminRequest{
		UserId: userID,
	})
	require.Error(t, err)

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.NotFound, statusErr.Code())
	assert.Equal(t, "user not found", statusErr.Message())
}

func TestRevokeAdmin_EmptyUserId(t *testing.T) {
	ctx, st := suite.New(t)

	_, err := st.AuthClient.RevokeAdmin(ctx, &grpcservicev1.RevokeAdminRequest{
		UserId: emptyID,
	})
	require.Error(t, err)

	statusErr, ok := status.FromError(err)
	require.True(t, ok)

	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
	assert.Equal(t, "user_id required", statusErr.Message())
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLen)
}
