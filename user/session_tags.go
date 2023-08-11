package user

// TagsFromMetadata updates the session state with the tags from the metadata.
func (s *SessionState) TagsFromMetadata(data map[string]interface{}) (updateSession bool) {
	developerID, keyFound := data["tyk_developer_id"].(string)
	if keyFound {
		s.MetaData["tyk_developer_id"] = developerID
		updateSession = true
	}

	// pteam-<id>, porg-<id>
	clientTags, ok := data["tags"].([]interface{})
	if ok {
		for _, tag := range clientTags {
			strTag, err := tag.(string)
			if err {
				continue
			}
			s.Tags = append(s.Tags, strTag)
		}
		updateSession = true
	}

	policies, ok := data["policies"].([]interface{})
	if ok {
		s.MetaData["policies"] = policies
		updateSession = true
	}

	return
}
