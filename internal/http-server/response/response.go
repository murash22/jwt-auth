package response

import (
	"encoding/json"
	"fmt"
	"net/http"
)

//type Response struct {
//	Status int         `json:"status"`
//	Error  string      `json:"error,omitempty"`
//	Data   interface{} `json:"data"`
//}

func SendResponse(w http.ResponseWriter, data interface{}) {
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		fmt.Println("error while encoding response", err)
		_, _ = w.Write([]byte("internal server error"))
	}
}
