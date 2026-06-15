package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T)  {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Caso Feliz: API Key válida",
			headers: http.Header{
				"Authorization": []string{"ApiKey mi-token-secreto-123"},
			},
			expectedKey:   "mi-token-secreto-123",
			expectedError: nil,
		},
		{
			name:          "Error: Cabecera Authorization ausente",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Error: Cabecera vacía",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Error: Prefijo incorrecto (ej. Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer mi-token-secreto-123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Error: Falta el token (solo dice ApiKey)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Error: Cabecera malformada completamente",
			headers: http.Header{
				"Authorization": []string{"loquesea sin sentido"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// Ejecutamos cada caso de prueba
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Verificar el error obtenido
			if tt.expectedError != nil {
				if gotErr == nil {
					t.Fatalf("se esperaba un error pero se obtuvo nil")
				}
				if gotErr.Error() != tt.expectedError.Error() {
					t.Errorf("error obtenido: %v, se esperaba: %v", gotErr, tt.expectedError)
				}
			} else if gotErr != nil {
				t.Fatalf("no se esperaba un error pero se obtuvo: %v", gotErr)
			}

			// Verificar la API Key obtenida
			if gotKey != tt.expectedKey {
				t.Errorf("key obtenida: %q, se esperaba: %q", gotKey, tt.expectedKey)
			}
		})
	}
}