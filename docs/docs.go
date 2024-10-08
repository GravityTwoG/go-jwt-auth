// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Marsel Abazbekov",
            "url": "https://github.com/GravityTwoG",
            "email": "marsel.ave@gmail.com"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/auth/config": {
            "get": {
                "description": "Get TTL of tokens",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Get tokens config",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ConfigDTO"
                        }
                    }
                }
            }
        },
        "/auth/delete-user": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Delete user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.CommonResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/login": {
            "post": {
                "description": "Logins user, also sets refresh token in cookie",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Login user",
                "parameters": [
                    {
                        "description": "LoginDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.LoginDTO"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.LoginResponseDTO"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/logout": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Logout user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.CommonResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/logout-all": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Logout all sessions",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.CommonResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/me": {
            "get": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Get current user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.UserDTO"
                        }
                    }
                }
            }
        },
        "/auth/me/active-sessions": {
            "get": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Get active sessions (list of refresh tokens)",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Get active sessions",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.SessionsDTO"
                        }
                    }
                }
            }
        },
        "/auth/me/auth-providers": {
            "get": {
                "description": "Get user auth providers",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Get user auth providers",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.UserAuthProviderDTO"
                            }
                        }
                    }
                }
            }
        },
        "/auth/oauth-providers": {
            "get": {
                "description": "Get supported oauth providers",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Get supported oauth providers",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/refresh-tokens": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Refreshes tokens, also sets new refresh token in cookie",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Refresh tokens",
                "parameters": [
                    {
                        "description": "RefreshTokensDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RefreshTokensDTO"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RefreshTokensResponseDTO"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/register": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Registers new user, also sets refresh token in cookie",
                "parameters": [
                    {
                        "description": "RegisterDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RegisterDTO"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RegisterResponseDTO"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/{provider}/connect-callback": {
            "post": {
                "description": "Connects oauth provider",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Connect oauth provider",
                "parameters": [
                    {
                        "description": "ConnectOAuthDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ConnectOAuthDTO"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ConnectOAuthResponseDTO"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/{provider}/consent": {
            "get": {
                "description": "Logins user, also sets refresh token in cookie",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Request redirect URL for oauth provider consent screen",
                "parameters": [
                    {
                        "type": "string",
                        "description": "redirectURL",
                        "name": "redirectURL",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.OAuthRedirectDTO"
                        }
                    }
                }
            }
        },
        "/auth/{provider}/login-callback": {
            "post": {
                "description": "Logins user, also sets refresh token in cookie",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Login user with oauth provider",
                "parameters": [
                    {
                        "description": "LoginWithOAuthDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.LoginWithOAuthDTO"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.LoginResponseDTO"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        },
        "/auth/{provider}/register-callback": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Auth"
                ],
                "summary": "Registers new user with oauth provider, also sets refresh token in cookie",
                "parameters": [
                    {
                        "description": "RegisterWithOAuthDTO",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RegisterWithOAuthDTO"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.RegisterResponseDTO"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "go-jwt-auth_internal_rest-api_dto.CommonResponseDTO": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.ConfigDTO": {
            "type": "object",
            "properties": {
                "accessTokenTTLsec": {
                    "type": "integer"
                },
                "refreshTokenTTLsec": {
                    "type": "integer"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.ConnectOAuthDTO": {
            "type": "object",
            "required": [
                "code",
                "redirectURL"
            ],
            "properties": {
                "code": {
                    "type": "string"
                },
                "redirectURL": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.ConnectOAuthResponseDTO": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.ErrorResponseDTO": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string"
                },
                "error": {
                    "type": "string"
                },
                "kind": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.LoginDTO": {
            "type": "object",
            "required": [
                "email",
                "fingerPrint",
                "password"
            ],
            "properties": {
                "email": {
                    "type": "string"
                },
                "fingerPrint": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.LoginResponseDTO": {
            "type": "object",
            "properties": {
                "accessToken": {
                    "type": "string"
                },
                "refreshToken": {
                    "type": "string"
                },
                "user": {
                    "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.UserDTO"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.LoginWithOAuthDTO": {
            "type": "object",
            "required": [
                "code",
                "fingerPrint",
                "redirectURL"
            ],
            "properties": {
                "code": {
                    "type": "string"
                },
                "fingerPrint": {
                    "type": "string"
                },
                "redirectURL": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.OAuthRedirectDTO": {
            "type": "object",
            "properties": {
                "redirectURL": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.RefreshTokensDTO": {
            "type": "object",
            "required": [
                "fingerPrint"
            ],
            "properties": {
                "fingerPrint": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.RefreshTokensResponseDTO": {
            "type": "object",
            "properties": {
                "accessToken": {
                    "type": "string"
                },
                "refreshToken": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.RegisterDTO": {
            "type": "object",
            "required": [
                "email",
                "fingerPrint",
                "password",
                "password2"
            ],
            "properties": {
                "email": {
                    "type": "string"
                },
                "fingerPrint": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                },
                "password2": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.RegisterResponseDTO": {
            "type": "object",
            "properties": {
                "accessToken": {
                    "type": "string"
                },
                "refreshToken": {
                    "type": "string"
                },
                "user": {
                    "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.UserDTO"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.RegisterWithOAuthDTO": {
            "type": "object",
            "required": [
                "code",
                "fingerPrint",
                "redirectURL"
            ],
            "properties": {
                "code": {
                    "type": "string"
                },
                "fingerPrint": {
                    "type": "string"
                },
                "redirectURL": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.SessionDTO": {
            "type": "object",
            "properties": {
                "createdAt": {
                    "type": "string"
                },
                "ip": {
                    "type": "string"
                },
                "updatedAt": {
                    "type": "string"
                },
                "userAgent": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.SessionsDTO": {
            "type": "object",
            "properties": {
                "sessions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/go-jwt-auth_internal_rest-api_dto.SessionDTO"
                    }
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.UserAuthProviderDTO": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "name": {
                    "type": "string"
                }
            }
        },
        "go-jwt-auth_internal_rest-api_dto.UserDTO": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "id": {
                    "type": "integer"
                }
            }
        }
    },
    "securityDefinitions": {
        "ApiKeyAuth": {
            "description": "Type \"Bearer\" followed by a space and JWT token.",
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8080",
	BasePath:         "/api",
	Schemes:          []string{},
	Title:            "Go JWT Auth API",
	Description:      "Go JWT Auth API example",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
