package auth

import (
	"context"
	"errors"
	"fmt"
	"grpc-service/internal/domain/models"
	"grpc-service/internal/lib/jwt"
	"grpc-service/internal/lib/logger/sl"
	"grpc-service/internal/storage"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.6 --name=UserSaver
type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.6 --name=UserProvider
type UserProvider interface {
	User(
		ctx context.Context,
		email string,
	) (models.User, error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
	GrantAdmin(
		ctx context.Context,
		userID int64,
	) error
	RevokeAdmin(
		ctx context.Context,
		userID int64,
	) error
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.6 --name=AppProvider
type AppProvider interface {
	App(
		ctx context.Context,
		appID int,
	) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
)

// New returns a new instance of the Auth service
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:         log,
		usrSaver:    userSaver,
		usrProvider: userProvider,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

// Login if user with given credentials exists in the system and returns access token.
//
// If user exists, but password incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid password", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Info("failed to get app", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
// If user with given username already exists, returns error.
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("operation", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered successfully")

	return id, nil
}

// IsAdmin checks if user is admin.
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("operation", op),
		slog.String("userID", fmt.Sprint(userID)),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)

	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to check if user is admin", sl.Err(err))

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checking if user is admin", slog.Bool("isAdmin", isAdmin))

	return isAdmin, nil
}

// GrantAdmin grants administrator privileges to the specified user.
func (a *Auth) GrantAdmin(
	ctx context.Context,
	userID int64,
) error {
	const op = "auth.GrantAdmin"

	log := a.log.With(
		slog.String("operation", op),
		slog.String("userID", fmt.Sprint(userID)),
	)

	log.Info("set user is admin")

	err := a.usrProvider.GrantAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))

			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		log.Error("failed to set user", sl.Err(err))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user granted admin successfully")

	return nil
}

// RevokeAdmin revokes administrator privileges from the specified user.
func (a *Auth) RevokeAdmin(
	ctx context.Context,
	userID int64,
) error {
	const op = "auth.RevokeAdmin"

	log := a.log.With(
		slog.String("operation", op),
		slog.String("userID", fmt.Sprint(userID)),
	)

	log.Info("unset user is admin")

	err := a.usrProvider.RevokeAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))

			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		log.Error("failed to unset user", sl.Err(err))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user revoke admin successfully")

	return nil
}
