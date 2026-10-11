package httpapi

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/reqid"
)

// errorLog receives the detail of errors the client sees only as "internal".
// ponytail: package-level because route constructors take no logger; pass NewRouter's logger down if more call sites need it.
var errorLog = logging.New(os.Stderr, "info", "json")

// writeLogged logs err on the server and answers a fixed message: database, transport and remote
// errors never reach the client.
func writeLogged(w http.ResponseWriter, r *http.Request, status int, code, message, event string, err error) {
	errorLog.Error(message, "request_id", RequestID(r), "event", event, "error_kind", err.Error())
	WriteError(w, r, status, code, message)
}

// writeInternal is writeLogged for the generic 500.
func writeInternal(w http.ResponseWriter, r *http.Request, event string, err error) {
	writeLogged(w, r, http.StatusInternalServerError, "internal", "internal server error", event, err)
}

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
