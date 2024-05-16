package gateway

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func (gw *Gateway) StreamHandler(w http.ResponseWriter, r *http.Request) {
	streamID := mux.Vars(r)["streamID"]

	var obj interface{}
	var code int

	switch r.Method {
	case http.MethodGet:
		obj, code = gw.handleGetStream(streamID)
	case http.MethodPost:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		obj, code = gw.handleCreateStream(streamID, b)
	case http.MethodPut:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		obj, code = gw.handleUpdateStream(streamID, b)
	case http.MethodDelete:
		obj, code = gw.handleDeleteStream(streamID)
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) StreamListHandler(w http.ResponseWriter, r *http.Request) {
	var obj interface{}
	var code int

	switch r.Method {
	case http.MethodGet:
		obj, code = gw.handleGetStreams()
	default:
		obj, code = apiError("method not allowed"), http.StatusMethodNotAllowed
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) readyHandler(w http.ResponseWriter, r *http.Request) {
	var obj interface{}
	var code int

	switch r.Method {
	case http.MethodGet:
		obj, code = gw.handleGetReady()
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleGetStream(ID string) (interface{}, int) {
	stream, err := gw.StreamClient.GetStream(ID)
	if err != nil {
		logrus.Error(err)
		return apiError("stream not found"), http.StatusNotFound
	}
	return stream, http.StatusOK
}

func (gw *Gateway) handleCreateStream(ID string, config []byte) (interface{}, int) {
	stream, err := gw.StreamClient.CreateStream(ID, config)
	if err != nil {
		logrus.Error(err)
		return apiError("failed to create stream"), http.StatusInternalServerError
	}
	err = createOrUpdateStreamFile(ID, config)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	return stream, http.StatusCreated
}

func (gw *Gateway) handleUpdateStream(ID string, config []byte) (interface{}, int) {
	stream, err := gw.StreamClient.UpdateStream(ID, config)
	if err != nil {
		logrus.Error(err)
		return apiError("failed to update stream"), http.StatusInternalServerError
	}

	err = createOrUpdateStreamFile(ID, config)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	return stream, http.StatusOK
}

func (gw *Gateway) handleDeleteStream(ID string) (interface{}, int) {
	stream, err := gw.StreamClient.DeleteStream(ID)
	if err != nil {
		logrus.Error(err)
		return apiError("failed to delete stream"), http.StatusInternalServerError
	}

	err = deleteStreamFile(ID)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	return stream, http.StatusOK
}

func (gw *Gateway) handleGetReady() (interface{}, int) {
	ready, err := gw.StreamClient.GetReady()
	if err != nil {
		logrus.Error(err)
		return apiError("service not ready"), http.StatusServiceUnavailable
	}
	return ready, http.StatusOK
}

func (gw *Gateway) handleGetStreams() (interface{}, int) {
	streams, err := gw.StreamClient.GetStreams()
	if err != nil {
		logrus.Error(err)
		return apiError("failed to get streams"), http.StatusInternalServerError
	}
	return streams, http.StatusOK
}

func (gw *Gateway) LoadStreamsFromDisk() error {
	// open the streams directory
	dir := path.Join("streams", "active")
	d, err := os.Open(dir)
	if err != nil {
		return err
	}

	// read all the files in the directory
	files, err := d.Readdir(-1)
	if err != nil {
		return err
	}

	// for each file, read the contents and create the stream
	for _, f := range files {
		fPath := path.Join(dir, f.Name())
		b, err := os.ReadFile(fPath)
		if err != nil {
			return err
		}

		name := strings.Split(f.Name(), ".")[0]
		log.Info("loading stream ID: ", name)
		_, err = gw.StreamClient.CreateStream(name, b)
		if err != nil {
			return err
		}
	}

	return nil
}

func createOrUpdateStreamFile(streamID string, config []byte) error {
	// try to open the stream file on disk
	filename := fmt.Sprintf("%s.yaml", streamID)
	filepath := path.Join("streams", "active", filename)
	f, err := os.Open(filepath)
	if err != nil {
		// if the file doesn't exist, create it
		if os.IsNotExist(err) {
			f, err = os.Create(filepath)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	defer f.Close()

	// write the new config to the file
	_, err = f.Write(config)
	if err != nil {
		return err
	}

	return nil
}

func deleteStreamFile(streamID string) error {
	filename := fmt.Sprintf("%s.yaml", streamID)
	filepath := path.Join("streams", "active", filename)
	err := os.Remove(filepath)
	if err != nil {
		return err
	}

	return nil
}
