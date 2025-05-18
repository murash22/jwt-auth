package response

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func SendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		fmt.Println("error while encoding response", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func SendTextResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	res := fmt.Sprint(data)
	_, err := w.Write([]byte(res))
	if err != nil {
		fmt.Println("error while encoding response", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

}
