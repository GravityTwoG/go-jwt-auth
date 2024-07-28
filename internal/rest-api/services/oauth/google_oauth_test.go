package oauth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go-jwt-auth/internal/rest-api/services/oauth"
)

func TestParseGoogleJWT(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    *oauth.GoogleTokenClaims
		wantErr error
	}{
		{
			name: "Should return token claims",
			args: args{
				token: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlMzQ1ZmQ3ZTRhOTcyNzFkZmZhOTkxZjVhODkzY2QxNmI4ZTA4MjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4OTUwNjEyMDg4MjgtZ3Q1N2tndGVyaWFjYjUxZGVpMjA1OTBwZzNvcGo5bTcuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4OTUwNjEyMDg4MjgtZ3Q1N2tndGVyaWFjYjUxZGVpMjA1OTBwZzNvcGo5bTcuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTgzOTU5NTgxOTAwNDk2ODA1MDciLCJlbWFpbCI6ImNyeXRla292QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiMndNVjYyTXhhc0Z6bnNmWUhKTmZzZyIsImlhdCI6MTcyMTA1NDA0MiwiZXhwIjoxNzIxMDU3NjQyfQ.M8u7EIlQVCX7rl1k0fzAxhWI7QmFCEj09sK-S7kGSNzXwC0gq-gFa5EErkFnJ_Dw4mrnL7NgSNw6Z7T8V96GE3KS2ns5j3CpFHnIHGg1DlFyCc2X20dK4ud9s9ifRr8jWT0tYrFVXAGSa3Ww-Xst_-MC6kntfKsRkpD5BPxx_5WqAQKcqz448w1tZktlXL2CCJ10uL6Agu4DFLmSVVsaiTVWexDmKiakGH9lLjK1mjRJvGlf-zsjFOkAj_5yWUM_Ji68u8zbvoLot1AUX4BxJsJNjJLvBguLjQ4VqE60WcmupB1ba38x9ZNJG1Mwoh2Ou3sIRib75ddujtTDwIoYgw",
			},
			want: &oauth.GoogleTokenClaims{
				Email: "crytekov@gmail.com",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := oauth.ParseGoogleJWT(tt.args.token)
			if err != nil {
				assert.Equal(t, tt.wantErr, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
