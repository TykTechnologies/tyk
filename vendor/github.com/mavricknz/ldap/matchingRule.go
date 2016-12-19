// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP MatchingRule functions.
package ldap

// At the moment just helper values for ServerSideSorting.
const (
	MatchingRule_numericStringOrderingMatch          = "2.5.13.9"                   // 1.3.6.1.4.1.1466.115.121.1.36
	MatchingRule_numericStringMatch                  = "2.5.13.8"                   // 1.3.6.1.4.1.1466.115.121.1.36
	MatchingRule_caseExactSubstringsMatch            = "2.5.13.7"                   // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_caseExactOrderingMatch              = "2.5.13.6"                   // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_caseExactMatch                      = "2.5.13.5"                   // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_caseIgnoreSubstringsMatch           = "2.5.13.4"                   // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_keywordMatch                        = "2.5.13.33"                  // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_wordMatch                           = "2.5.13.32"                  // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_directoryStringFirstComponentMatch  = "2.5.13.31"                  // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_objectIdentifierFirstComponentMatch = "2.5.13.30"                  // 1.3.6.1.4.1.1466.115.121.1.38
	MatchingRule_caseIgnoreOrderingMatch             = "2.5.13.3"                   // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_integerFirstComponentMatch          = "2.5.13.29"                  // 1.3.6.1.4.1.1466.115.121.1.27
	MatchingRule_generalizedTimeOrderingMatch        = "2.5.13.28"                  // 1.3.6.1.4.1.1466.115.121.1.24
	MatchingRule_generalizedTimeMatch                = "2.5.13.27"                  // 1.3.6.1.4.1.1466.115.121.1.24
	MatchingRule_protocolInformationMatch            = "2.5.13.24"                  // 1.3.6.1.4.1.1466.115.121.1.42
	MatchingRule_uniqueMemberMatch                   = "2.5.13.23"                  // 1.3.6.1.4.1.1466.115.121.1.34
	MatchingRule_presentationAddressMatch            = "2.5.13.22"                  // 1.3.6.1.4.1.1466.115.121.1.43
	MatchingRule_telephoneNumberSubstringsMatch      = "2.5.13.21"                  // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_telephoneNumberMatch                = "2.5.13.20"                  // 1.3.6.1.4.1.1466.115.121.1.50
	MatchingRule_caseIgnoreMatch                     = "2.5.13.2"                   // 1.3.6.1.4.1.1466.115.121.1.15
	MatchingRule_octetStringSubstringsMatch          = "2.5.13.19"                  // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_octetStringOrderingMatch            = "2.5.13.18"                  // 1.3.6.1.4.1.1466.115.121.1.40
	MatchingRule_octetStringMatch                    = "2.5.13.17"                  // 1.3.6.1.4.1.1466.115.121.1.40
	MatchingRule_bitStringMatch                      = "2.5.13.16"                  // 1.3.6.1.4.1.1466.115.121.1.6
	MatchingRule_integerOrderingMatch                = "2.5.13.15"                  // 1.3.6.1.4.1.1466.115.121.1.27
	MatchingRule_integerMatch                        = "2.5.13.14"                  // 1.3.6.1.4.1.1466.115.121.1.27
	MatchingRule_booleanMatch                        = "2.5.13.13"                  // 1.3.6.1.4.1.1466.115.121.1.7
	MatchingRule_caseIgnoreListSubstringsMatch       = "2.5.13.12"                  // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_caseIgnoreListMatch                 = "2.5.13.11"                  // 1.3.6.1.4.1.1466.115.121.1.41
	MatchingRule_numericStringSubstringsMatch        = "2.5.13.10"                  // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_distinguishedNameMatch              = "2.5.13.1"                   // 1.3.6.1.4.1.1466.115.121.1.12
	MatchingRule_objectIdentifierMatch               = "2.5.13.0"                   // 1.3.6.1.4.1.1466.115.121.1.38
	MatchingRule_authPasswordMatch                   = "1.3.6.1.4.1.4203.1.2.3"     // 1.3.6.1.4.1.4203.1.1.2 DESC 'authentication password matching rule'
	MatchingRule_authPasswordExactMatch              = "1.3.6.1.4.1.4203.1.2.2"     // 1.3.6.1.4.1.4203.1.1.2 DESC 'authentication password exact matching rule'
	MatchingRule_caseExactIA5SubstringsMatch         = "1.3.6.1.4.1.26027.1.4.902"  // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_partialDateAndTimeMatchingRule      = "1.3.6.1.4.1.26027.1.4.7"    // 1.3.6.1.4.1.1466.115.121.1.24
	MatchingRule_relativeTimeLTOrderingMatch         = "1.3.6.1.4.1.26027.1.4.6"    // 1.3.6.1.4.1.1466.115.121.1.24
	MatchingRule_relativeTimeGTOrderingMatch         = "1.3.6.1.4.1.26027.1.4.5"    // 1.3.6.1.4.1.1466.115.121.1.24
	MatchingRule_historicalCsnOrderingMatch          = "1.3.6.1.4.1.26027.1.4.4"    // 1.3.6.1.4.1.1466.115.121.1.40
	MatchingRule_ds_mr_user_password_equality        = "1.3.6.1.4.1.26027.1.4.3"    // 1.3.6.1.4.1.26027.1.3.1 DESC 'user password matching rule'
	MatchingRule_ds_mr_user_password_exact           = "1.3.6.1.4.1.26027.1.4.2"    // 1.3.6.1.4.1.26027.1.3.1 DESC 'user password exact matching rule'
	MatchingRule_ds_mr_double_metaphone_approx       = "1.3.6.1.4.1.26027.1.4.1"    // 1.3.6.1.4.1.26027.1.3.1 DESC 'Double Metaphone Approximate Match'
	MatchingRule_caseIgnoreIA5SubstringsMatch        = "1.3.6.1.4.1.1466.109.114.3" // 1.3.6.1.4.1.1466.115.121.1.58
	MatchingRule_caseIgnoreIA5Match                  = "1.3.6.1.4.1.1466.109.114.2" // 1.3.6.1.4.1.1466.115.121.1.26
	MatchingRule_caseExactIA5Match                   = "1.3.6.1.4.1.1466.109.114.1" // 1.3.6.1.4.1.1466.115.121.1.26
	MatchingRule_uuidOrderingMatch                   = "1.3.6.1.1.16.3"             // 1.3.6.1.1.16.1
	MatchingRule_uuidMatch                           = "1.3.6.1.1.16.2"             // 1.3.6.1.1.16.1
)
