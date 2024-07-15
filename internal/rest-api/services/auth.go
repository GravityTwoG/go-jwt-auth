package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
	"github.com/google/uuid"
)

const InvalidRefreshToken = "INVALID_REFRESH_TOKEN"
const RefreshTokenExpired = "REFRESH_TOKEN_EXPIRED"
const RefreshTokenNotFound = "REFRESH_TOKEN_NOT_FOUND"
const InvalidUserAgent = "INVALID_USER_AGENT"
const InvalidFingerPrint = "INVALID_FINGER_PRINT"

type Tokens struct {
	AccessToken  string
	RefreshToken entities.RefreshToken
}

type RefreshTokensDTO struct {
	OldToken    string
	IP          string
	UserAgent   string
	FingerPrint string
}

type RefreshTokenRepository interface {
	Create(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	Update(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	GetByToken(
		ctx context.Context,
		token string,
	) (*entities.RefreshToken, domainerrors.ErrDomain)

	GetByUserID(
		ctx context.Context,
		id uint,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	Delete(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	DeleteByUserID(
		ctx context.Context,
		userID uint,
	) domainerrors.ErrDomain

	DeleteExpired(
		ctx context.Context) domainerrors.ErrDomain
}

type AuthService interface {
	Register(
		ctx context.Context,
		dto *dto.RegisterDTO,
	) (*entities.User, domainerrors.ErrDomain)

	Login(
		ctx context.Context,
		dto *dto.LoginDTO,
		ip string,
		userAgent string,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	RegisterWithGoogle(
		ctx context.Context,
		dto *dto.RegisterWithGoogleDTO,
	) (*entities.User, domainerrors.ErrDomain)

	RequestGoogleConsentURL(
		ctx context.Context,
		redirectURL string,
	) string

	LoginWithGoogle(
		ctx context.Context,
		ip string,
		userAgent string,
		dto *dto.LoginWithGoogleDTO,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	RefreshTokens(
		ctx context.Context,
		dto *RefreshTokensDTO,
	) (*Tokens, domainerrors.ErrDomain)

	GetUserByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domainerrors.ErrDomain)

	GetActiveSessions(
		ctx context.Context,
		id uint,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	GetConfig(ctx context.Context) *dto.ConfigDTO

	Logout(
		ctx context.Context,
		refreshToken string,
		userAgent string,
	) domainerrors.ErrDomain

	LogoutAll(
		ctx context.Context,
		refreshToken string,
		userAgent string,
	) domainerrors.ErrDomain

	RunScheduledTasks(ctx context.Context)
}

type authService struct {
	trManager *manager.Manager

	userService UserService

	refreshTokenRepository RefreshTokenRepository

	jwtPrivateKey      *rsa.PrivateKey
	jwtPublicKey       *rsa.PublicKey
	accessTokenTTLsec  int
	refreshTokenTTLsec int

	googleClientID     string
	googleClientSecret string
}

func NewAuthService(
	trManager *manager.Manager,
	userService UserService,
	refreshTokenRepository RefreshTokenRepository,
	jwtPrivateKey *rsa.PrivateKey,
	jwtAccessTTL int,
	refreshTokenTTL int,
	googleClientID string,
	googleClientSecret string,
) AuthService {

	jwtPrivateKey.Public()

	return &authService{
		trManager: trManager,

		userService: userService,

		refreshTokenRepository: refreshTokenRepository,

		jwtPrivateKey:      jwtPrivateKey,
		jwtPublicKey:       &jwtPrivateKey.PublicKey,
		accessTokenTTLsec:  jwtAccessTTL,
		refreshTokenTTLsec: refreshTokenTTL,

		googleClientID:     googleClientID,
		googleClientSecret: googleClientSecret,
	}
}

func (s *authService) Register(
	ctx context.Context,
	registerDTO *dto.RegisterDTO,
) (*entities.User, domainerrors.ErrDomain) {

	return s.userService.Register(ctx, registerDTO)
}

func (s *authService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
	ip string,
	userAgent string,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	user, err := s.userService.Login(ctx, loginDTO)
	if err != nil {
		return nil, nil, err
	}

	tokens, err := s.createTokensPair(
		ctx,
		user,
		ip,
		userAgent,
		loginDTO.FingerPrint,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *authService) createTokensPair(
	ctx context.Context,
	user *entities.User,
	ip string,
	userAgent string,
	fingerPrint string,
) (*Tokens, domainerrors.ErrDomain) {
	accessToken, err := newJWT(
		user,
		s.accessTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := newJWT(
		user,
		s.refreshTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	refreshTokenEntity := entities.NewRefreshToken(
		refreshToken,
		user.GetID(),
		s.refreshTokenTTLsec,
		ip,
		userAgent,
		fingerPrint,
	)

	err = s.refreshTokenRepository.Create(ctx, refreshTokenEntity)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshTokenEntity,
	}, nil
}

func (s *authService) RegisterWithGoogle(
	ctx context.Context,
	registerWithGoogleDTO *dto.RegisterWithGoogleDTO,
) (*entities.User, domainerrors.ErrDomain) {
	email, err := s.fetchGoogleUserEmail(
		ctx,
		registerWithGoogleDTO.Code,
		registerWithGoogleDTO.RedirectURL,
	)

	if err != nil {
		return nil, err
	}

	password := uuid.New().String()

	registerDTO := &dto.RegisterDTO{
		Email:     email,
		Password:  password,
		Password2: password,
	}

	return s.userService.Register(ctx, registerDTO)
}

func (s *authService) RequestGoogleConsentURL(
	ctx context.Context,
	redirectURL string,
) string {
	// https://developers.google.com/identity/protocols/oauth2/web-server#httprest
	endpoint := "https://accounts.google.com/o/oauth2/v2/auth"

	responseType := "code"

	// https://developers.google.com/identity/protocols/oauth2/scopes#oauth2
	scope := "https://www.googleapis.com/auth/userinfo.email"

	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s",
		endpoint,
		s.googleClientID,
		redirectURL,
		responseType,
		scope,
	)
}

func (s *authService) LoginWithGoogle(
	ctx context.Context,
	ip string,
	userAgent string,
	dto *dto.LoginWithGoogleDTO,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	email, err := s.fetchGoogleUserEmail(
		ctx,
		dto.Code,
		dto.RedirectURL,
	)
	if err != nil {
		return nil, nil, err
	}

	user, err := s.userService.GetByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}

	tokens, err := s.createTokensPair(
		ctx,
		user,
		ip,
		userAgent,
		dto.FingerPrint,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *authService) fetchGoogleUserEmail(
	ctx context.Context,
	code string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	endpoint := "https://www.googleapis.com/oauth2/v4/token"

	client := &http.Client{}

	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", s.googleClientID)
	form.Add("client_secret", s.googleClientSecret)
	form.Add("redirect_uri", redirectURL)
	form.Add("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(
		ctx, "POST", endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", domainerrors.NewErrUnknown(
			fmt.Errorf("unexpected status code: %d", resp.StatusCode),
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	fmt.Println(string(body))

	var dto struct {
		IDToken string `json:"id_token"`
	}

	err = json.Unmarshal(body, &dto)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	claims, err := ParseGoogleJWT(dto.IDToken)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return claims.Email, nil
}

func (s *authService) RefreshTokens(
	ctx context.Context,
	dto *RefreshTokensDTO,
) (*Tokens, domainerrors.ErrDomain) {

	tokenClaims, jwtErr := VerifyAndParseJWT(dto.OldToken, s.jwtPublicKey)
	if jwtErr != nil {
		return nil, domainerrors.NewErrInvalidInput(
			InvalidRefreshToken,
			"invalid or expired refresh token",
		)
	}

	var tokens *Tokens = nil
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		tokens, domainError = s.refreshTokens(
			ctx,
			dto,
			tokenClaims.ID,
		)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.RefreshTokens transaction err: %v", err)
	}

	return tokens, domainError
}

func (s *authService) refreshTokens(
	ctx context.Context,
	dto *RefreshTokensDTO,
	userID uint,
) (*Tokens, domainerrors.ErrDomain) {
	refreshTokenEntity, err := s.refreshTokenRepository.
		GetByToken(ctx, dto.OldToken)

	// Token with valid signature and expiration provided,
	// but this token doesn't exist in DB.
	// Maybe was stolen and deleted by another person.
	if err != nil && err.Kind() == domainerrors.EntityNotFound {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			RefreshTokenNotFound,
			"refresh token not found. All refresh tokens were deleted",
		)
	}
	if err != nil {
		return nil, err
	}

	if refreshTokenEntity.GetUserAgent() != dto.UserAgent {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			InvalidUserAgent,
			"invalid user agent. All refresh tokens were deleted",
		)
	}

	if refreshTokenEntity.GetFingerPrint() != dto.FingerPrint {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			InvalidFingerPrint,
			"invalid finger print. All refresh tokens were deleted",
		)
	}

	// create new access token
	accessToken, err := newJWT(
		refreshTokenEntity.GetUser(),
		s.accessTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	// create new refresh token
	newRefreshToken, err := newJWT(
		refreshTokenEntity.GetUser(),
		s.refreshTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	refreshTokenEntity.SetToken(newRefreshToken)
	err = s.refreshTokenRepository.Update(ctx, refreshTokenEntity)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshTokenEntity,
	}, nil
}

func (s *authService) GetUserByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {

	return s.userService.GetByID(ctx, id)
}

func (s *authService) GetActiveSessions(
	ctx context.Context,
	id uint,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {

	return s.refreshTokenRepository.GetByUserID(ctx, id)
}

func (s *authService) GetConfig(
	ctx context.Context,
) *dto.ConfigDTO {
	return &dto.ConfigDTO{
		AccessTokenTTLsec:  s.accessTokenTTLsec,
		RefreshTokenTTLsec: s.refreshTokenTTLsec,
	}
}

func (s *authService) Logout(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		domainError = s.logout(ctx, refreshToken, userAgent)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.Logout transaction err: %v", err)
	}

	return domainError
}

func (s *authService) logout(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {

	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	if existingRefreshToken.GetUserAgent() != userAgent {
		return domainerrors.NewErrInvalidInput(
			InvalidUserAgent,
			"invalid user agent",
		)
	}

	return s.refreshTokenRepository.
		Delete(ctx, existingRefreshToken)
}

func (s *authService) LogoutAll(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		domainError = s.logoutAll(ctx, refreshToken, userAgent)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.LogoutAll transaction err: %v", err)
	}

	return domainError
}

func (s *authService) logoutAll(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {

	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)

	if err != nil {
		return err
	}

	if existingRefreshToken.GetUserAgent() != userAgent {
		return domainerrors.NewErrInvalidInput(
			InvalidUserAgent,
			"invalid user agent",
		)
	}

	return s.refreshTokenRepository.DeleteByUserID(
		ctx,
		existingRefreshToken.GetUserID(),
	)
}

func (s *authService) RunScheduledTasks(ctx context.Context) {
	for {
		err := s.refreshTokenRepository.DeleteExpired(ctx)
		if err != nil {
			log.Printf("authService: Error deleting expired refresh tokens: %v", err)
		} else {
			log.Println("authService: Deleted expired refresh tokens")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(1) * time.Minute):
		}
	}
}
