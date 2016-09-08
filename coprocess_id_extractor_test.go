// +build coprocess
// +build !python

package main

import (

)

var IdExtractorCoProcessDef string = `

	{
		"name": "Tyk Test API - IPCONF Fail",
		"api_id": "1",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "2100-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"event_handlers": {
			"events": {
				"AuthFailure": [
								{
										"handler_name":"cp_dynamic_handler",
										"handler_meta": {
												"name": "my_handler"
										}
								}
						]
			}
		},
    "custom_middleware": {
      "pre": [
        {
          "name": "MyPreMiddleware",
          "require_session": false
        }
      ],
      "driver": "python"
    },
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://httpbin.org",
			"strip_listen_path": false
		}
	}
`
