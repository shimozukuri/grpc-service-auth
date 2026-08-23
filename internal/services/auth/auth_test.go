package auth_test

import (
	"context"
	"errors"
	"grpc-service/internal/domain/models"
	"grpc-service/internal/lib/logger/handlers/slogdiscard"
	"grpc-service/internal/services/auth"
	"grpc-service/internal/services/auth/mocks"
	"grpc-service/internal/storage"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	passDefaultLen = 10
	testTokenTTL   = time.Hour
)

type authMocks struct {
	userSaver    *mocks.UserSaver
	userProvider *mocks.UserProvider
	appProvider  *mocks.AppProvider
}

func TestAuth_RegisterNewUser(t *testing.T) {
	saveErr := errors.New("failed to save user")

	testCases := []struct {
		name     string
		email    string
		password string

		respErr error
		mockErr error

		skipSave bool
	}{
		{
			name:     "success",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
		},
		{
			name:     "user exists",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			respErr:  auth.ErrUserExists,
			mockErr:  storage.ErrUserExists,
		},
		{
			name:     "hash password error",
			email:    gofakeit.Email(),
			password: strings.Repeat("a", 73),
			respErr:  bcrypt.ErrPasswordTooLong,
			skipSave: true,
		},
		{
			name:     "save user error",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			respErr:  saveErr,
			mockErr:  saveErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			a, m := newAuth(t)

			if !tc.skipSave {
				m.userSaver.
					On(
						"SaveUser",
						ctx,
						tc.email,
						mock.Anything,
					).
					Return(int64(1), tc.mockErr).
					Once()
			}

			userID, err := a.RegisterNewUser(
				ctx,
				tc.email,
				tc.password,
			)

			if tc.respErr == nil {
				require.NoError(t, err)
				require.Equal(t, int64(1), userID)
				return
			}

			require.Error(t, err)
			require.ErrorIs(t, err, tc.respErr)
			require.Zero(t, userID)
		})
	}
}

func TestAuth_Login(t *testing.T) {
	userErr := errors.New("failed to get user")
	appErr := errors.New("failed to get app")

	email := gofakeit.Email()
	password := randomFakePassword()

	passHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	require.NoError(t, err)

	testUser := models.User{
		ID:       1,
		Email:    email,
		PassHash: passHash,
	}

	testApp := models.App{
		ID:     1,
		Secret: "test-secret",
	}

	testCases := []struct {
		name     string
		email    string
		password string
		appID    int

		user    models.User
		userErr error

		app    models.App
		appErr error

		expectedErr error
		callApp     bool
	}{
		{
			name:     "success",
			email:    email,
			password: password,
			appID:    1,
			user:     testUser,
			app:      testApp,
			callApp:  true,
		},
		{
			name:        "user not found",
			email:       email,
			password:    password,
			appID:       1,
			userErr:     storage.ErrUserNotFound,
			expectedErr: auth.ErrInvalidCredentials,
		},
		{
			name:        "user provider error",
			email:       email,
			password:    password,
			appID:       1,
			userErr:     userErr,
			expectedErr: userErr,
		},
		{
			name:        "invalid password",
			email:       email,
			password:    "wrong-password",
			appID:       1,
			user:        testUser,
			expectedErr: auth.ErrInvalidCredentials,
		},
		{
			name:        "app not found",
			email:       email,
			password:    password,
			appID:       1,
			user:        testUser,
			appErr:      storage.ErrAppNotFound,
			expectedErr: auth.ErrInvalidCredentials,
			callApp:     true,
		},
		{
			name:        "app provider error",
			email:       email,
			password:    password,
			appID:       1,
			user:        testUser,
			appErr:      appErr,
			expectedErr: appErr,
			callApp:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			a, m := newAuth(t)

			m.userProvider.
				On("User", ctx, tc.email).
				Return(tc.user, tc.userErr).
				Once()

			if tc.callApp {
				m.appProvider.
					On("App", ctx, tc.appID).
					Return(tc.app, tc.appErr).
					Once()
			}

			token, err := a.Login(
				ctx,
				tc.email,
				tc.password,
				tc.appID,
			)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				require.Empty(t, token)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, token)
		})
	}
}

func TestAuth_IsAdmin(t *testing.T) {
	providerErr := errors.New("failed to check user")

	testCases := []struct {
		name    string
		userID  int64
		isAdmin bool

		respErr error
		mockErr error
	}{
		{
			name:    "success true",
			userID:  1,
			isAdmin: true,
		},
		{
			name:    "success false",
			userID:  1,
			isAdmin: false,
		},
		{
			name:    "user not found",
			userID:  1,
			respErr: auth.ErrUserNotFound,
			mockErr: storage.ErrUserNotFound,
		},
		{
			name:    "user provider error",
			userID:  1,
			respErr: providerErr,
			mockErr: providerErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			a, m := newAuth(t)

			m.userProvider.
				On("IsAdmin", ctx, tc.userID).
				Return(tc.isAdmin, tc.mockErr).
				Once()

			isAdmin, err := a.IsAdmin(ctx, tc.userID)

			if tc.respErr == nil {
				require.NoError(t, err)
				require.Equal(t, tc.isAdmin, isAdmin)
				return
			}

			require.Error(t, err)
			require.ErrorIs(t, err, tc.respErr)
			require.False(t, isAdmin)
		})
	}
}

func TestAuth_GrantAdmin(t *testing.T) {
	providerErr := errors.New("failed to grant admin")

	testCases := []struct {
		name   string
		userID int64

		respErr error
		mockErr error
	}{
		{
			name:   "success",
			userID: 1,
		},
		{
			name:    "user not found",
			userID:  1,
			respErr: auth.ErrUserNotFound,
			mockErr: storage.ErrUserNotFound,
		},
		{
			name:    "user provider error",
			userID:  1,
			respErr: providerErr,
			mockErr: providerErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			a, m := newAuth(t)

			m.userProvider.
				On("GrantAdmin", ctx, tc.userID).
				Return(tc.mockErr).
				Once()

			err := a.GrantAdmin(ctx, tc.userID)

			if tc.respErr == nil {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.ErrorIs(t, err, tc.respErr)
		})
	}
}

func TestAuth_RevokeAdmin(t *testing.T) {
	providerErr := errors.New("failed to revoke admin")

	testCases := []struct {
		name   string
		userID int64

		respErr error
		mockErr error
	}{
		{
			name:   "success",
			userID: 1,
		},
		{
			name:    "user not found",
			userID:  1,
			respErr: auth.ErrUserNotFound,
			mockErr: storage.ErrUserNotFound,
		},
		{
			name:    "user provider error",
			userID:  1,
			respErr: providerErr,
			mockErr: providerErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			a, m := newAuth(t)

			m.userProvider.
				On("RevokeAdmin", ctx, tc.userID).
				Return(tc.mockErr).
				Once()

			err := a.RevokeAdmin(ctx, tc.userID)

			if tc.respErr == nil {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.ErrorIs(t, err, tc.respErr)
		})
	}
}

func newAuth(t *testing.T) (*auth.Auth, authMocks) {
	t.Helper()

	userSaverMock := mocks.NewUserSaver(t)
	userProviderMock := mocks.NewUserProvider(t)
	appProviderMock := mocks.NewAppProvider(t)

	m := authMocks{
		userSaver:    userSaverMock,
		userProvider: userProviderMock,
		appProvider:  appProviderMock,
	}

	a := auth.New(
		slogdiscard.NewDiscardLogger(),
		userSaverMock,
		userProviderMock,
		appProviderMock,
		testTokenTTL,
	)

	return a, m
}

func randomFakePassword() string {
	return gofakeit.Password(
		true,
		true,
		true,
		true,
		true,
		passDefaultLen,
	)
}
