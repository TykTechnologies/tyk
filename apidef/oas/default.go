package oas

import (
	"fmt"
	neturl "net/url"
)

type TykExtensionConfigParams struct {
	UpstreamURL string
	ListenPath  string
}

func (s *OAS) BuildDefaultTykExtension(overRideValues TykExtensionConfigParams) error {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway == nil {
		xTykAPIGateway = &XTykAPIGateway{}
		s.SetTykExtension(xTykAPIGateway)
	}

	if xTykAPIGateway.Info.Name == "" {
		xTykAPIGateway.Info.Name = s.Info.Title
	}

	xTykAPIGateway.Info.State.Active = true
	xTykAPIGateway.Info.State.Internal = false

	if overRideValues.ListenPath != "" {
		xTykAPIGateway.Server.ListenPath.Value = overRideValues.ListenPath
	} else if xTykAPIGateway.Server.ListenPath.Value == "" {
		xTykAPIGateway.Server.ListenPath.Value = "/"
	}

	var (
		url *neturl.URL
		err error
	)

	if overRideValues.UpstreamURL != "" {
		url, err = neturl.Parse(overRideValues.UpstreamURL)
		if err != nil || !url.IsAbs() {
			return fmt.Errorf("invalid upstream URL")
		}

	} else {
		if len(s.Servers) == 0 {
			return fmt.Errorf("servers object is empty in OAS")
		}

		serverURL := s.Servers[0].URL
		url, err = neturl.Parse(serverURL)
		if err != nil || !url.IsAbs() {
			return fmt.Errorf("Error validating servers entry in OAS: Please update %q to be a valid url or pass a valid url with upstreamURL query param", serverURL)
		}

	}

	xTykAPIGateway.Upstream.URL = url.String()

	return nil
}
