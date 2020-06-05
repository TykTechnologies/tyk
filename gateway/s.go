package gateway

/*
func handleAddOrUpdates(keyName string, r *http.Request, isHashed bool) (interface{}, int) {
	suppressReset := r.URL.Query().Get("suppress_reset") == "1"

	// decode payload
	newSession := user.SessionState{}

	contents, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewReader(contents))

	if err := json.Unmarshal(contents, &newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	mw := BaseMiddleware{}
	mw.ApplyPolicies(&newSession)

	// DO ADD OR UPDATE

	// get original session in case of update and preserve fields that SHOULD NOT be updated
	originalKey := user.SessionState{}
	if r.Method == http.MethodPut {
		found := false
		for apiID := range newSession.AccessRights {
			originalKey, found = getKeyDetail(keyName, apiID, isHashed)
			if found {
				break
			}
		}
		if !found {
			log.Error("Could not find key when updating")
			return apiError("Key is not found"), http.StatusNotFound
		}

		// don't change fields related to quota and rate limiting if was passed as "suppress_reset=1"
		if suppressReset {
			// save existing quota_renews and last_updated if suppress_reset was passed
			// (which means don't reset quota or rate counters)
			// - leaving quota_renews as 0 will force quota limiter to start new renewal period
			// - setting new last_updated with force rate limiter to start new "per" rating period

			// on session level
			newSession.QuotaRenews = originalKey.QuotaRenews
			newSession.LastUpdated = originalKey.LastUpdated

			// on ACL API limit level
			for apiID, access := range originalKey.AccessRights {
				if access.Limit == nil {
					continue
				}
				if newAccess, ok := newSession.AccessRights[apiID]; ok && newAccess.Limit != nil {
					newAccess.Limit.QuotaRenews = access.Limit.QuotaRenews
					newSession.AccessRights[apiID] = newAccess
				}
			}
		}
	} else {
		newSession.DateCreated = time.Now()
	}

	// Update our session object (create it)
	if newSession.BasicAuthData.Password != "" {
		// If we are using a basic auth user, then we need to make the keyname explicit against the OrgId in order to differentiate it
		// Only if it's NEW
		switch r.Method {
		case http.MethodPost:
			keyName = generateToken(newSession.OrgID, keyName)
			// It's a create, so lets hash the password
			setSessionPassword(&newSession)
		case http.MethodPut:
			if originalKey.BasicAuthData.Password != newSession.BasicAuthData.Password {
				// passwords dont match assume it's new, lets hash it
				log.Debug("Passwords dont match, original: ", originalKey.BasicAuthData.Password)
				log.Debug("New: newSession.BasicAuthData.Password")
				log.Debug("Changing password")
				setSessionPassword(&newSession)
			}
		}
	}

	if err := doAddOrUpdate(keyName, &newSession, suppressReset, isHashed); err != nil {
		return apiError("Failed to create key, ensure security settings are correct."), http.StatusInternalServerError
	}

	action := "modified"
	event := EventTokenUpdated
	if r.Method == http.MethodPost {
		action = "added"
		event = EventTokenCreated
	}
	FireSystemEvent(event, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key modified."},
		Org:              newSession.OrgID,
		Key:              keyName,
	})

	response := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: action,
	}

	// add key hash for newly created key
	if config.Global().HashKeys && r.Method == http.MethodPost {
		if isHashed {
			response.KeyHash = keyName
		} else {
			response.KeyHash = storage.HashKey(keyName)
		}
	}

	return response, http.StatusOK
}
*/