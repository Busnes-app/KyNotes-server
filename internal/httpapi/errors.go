package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/Busness-app/kynotes-server/internal/reqid"
)

type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorBody{Error: ErrorDetail{Code: code, Message: message, RequestID: RequestID(r)}})
}
func RequestID(r *http.Request) string {
	return reqid.FromContext(r.Context())
}
