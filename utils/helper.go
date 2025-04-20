package utils

import (
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

func ExtractHttpBody(reader io.ReadCloser) string {
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		logrus.Fatal(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func ProcessRequest(request *http.Request, err error) error {
	resp, err := http.DefaultClient.Do(request)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			return nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, ExtractHttpBody(resp.Body))
			return err
		}
	} else {
		return err
	}
}
